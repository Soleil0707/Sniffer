# from queue import Queue
from socket import *
from struct import *
import time
import threading


class parse_thread(threading.Thread):
    """ 自定义解析线程类，相比于threading增加了pause、resume、stop的功能
    并且对run函数做了修改，run会循环执行，每次解析一个数据包，无数据包时会空转
    TODO: 添加信号量，无包时sleep，有包时被唤醒
    """
    def __init__(self, packet_queue):
        super(parse_thread, self).__init__()
        # 待解析的包队列(每个元素是类型、包、时间的三元组)
        self.packet_wait_parse_queue = packet_queue

        # 捕获到的包队列(每个元素是一个完整的数据包)
        self.packet_list = list()
        # 数据包头队列（每个元素是一个json格式数据，保存一个包的头部信息）
        self.packet_head = list()
        # 提取到的重要信息（每个元素也是一个list，依次为序号 时间 源地址 源端口 目的地址 目的端口 协议类型）
        self.packet_info = list()
        # 记录包的序号，从1开始（不是从0开始）
        self.packet_index = 0
        # 下一个显示的包的序号
        self.packet_display_index = 1

        self.__flag = threading.Event()     # 用于暂停线程的标识
        self.__flag.set()       # 设置为True
        self.__running = threading.Event()      # 用于停止线程的标识
        self.__running.set()      # 将running设置为True

    def run(self):
        while self.__running.isSet():
            self.__flag.wait()      # 为True时立即返回, 为False时阻塞直到内部的标识位为True后返回
            # TODO 进程同步相关操作
            if self.packet_wait_parse_queue.empty():
                continue
            # pkt_time的时间格式为Unix时间戳
            l2_type, l2_packet, pkt_time = self.packet_wait_parse_queue.get()
            self.packet_index += 1
            self.packet_list.append(l2_packet)
            # 解析包头json至packet_head
            info = new_a_info()
            info['num'] = str(self.packet_index)
            info['time'] = time.strftime("%Y-%m-%d-%H:%M:%S", time.localtime(pkt_time))
            packet_head_json = {}
            info, packet_head_json = parse_a_packet(l2_packet, info, packet_head_json)
            self.packet_info.append(info)
            self.packet_head.append(packet_head_json)

    def pause(self):
        """ 线程暂停 """
        self.__flag.clear()     # 设置为False, 让线程阻塞

    def resume(self):
        """ 线程继续运行 """
        self.__flag.set()    # 设置为True, 让线程停止阻塞

    def stop(self):
        """ 线程退出 """
        self.__flag.set()       # 将线程从暂停状态恢复, 如何已经暂停的话
        self.__running.clear()        # 设置为False


"""
B   8bit
H   16bit
I   32bit
"""


def new_a_info():
    """创建一个info的字典，其中记录一个包的重要信息，如源和目的地址和端口等"""
    info = {'num': '-1',
            'time': '-1',
            'src_addr': '0',
            'src_port': '-',
            'dst_addr': '0',
            'dst_port': '-',
            'type': '-'}
    return info


def parse_pacp_file(filename):
    pcap = open(filename, 'rb')
    pcap_header = pcap.read(24)

    pkt_header = pcap.read(16)
    time1, time2, cap_len, pkt_len = unpack("IIII", pkt_header)
    l2_packet = pcap.read(pkt_len)

    # packet_info_list(序号 时间 源地址 源端口 目的地址 目的端口 协议类型)
    # packet_head_json
    # packet_bin_list
    info = new_a_info()
    packet_head_json = {}
    parse_a_packet(l2_packet, info, packet_head_json)


def parse_a_packet(packet, info, packet_head_json):
    """ 解析一个数据包，最后返回info和json
    """
    # 解析数据包的链路层
    ip_packet, eth_header = parse_eth(packet)

    info['src_addr'] = eth_header['Source']
    info['dst_addr'] = eth_header['Destination']
    info['type'] = 'Ethernet'
    packet_head_json['Ethernet'] = eth_header

    if eth_header['Type'] == '0x0800':
        trans_packet, ip_header = parse_ipv4(ip_packet)
        info['src_addr'] = ip_header['Source_Address']
        info['dst_addr'] = ip_header['Destination_Address']
        info['type'] = 'IPv4'
        packet_head_json['Internet Protocol Version 4'] = ip_header

        if ip_header['Protocol'] == 6:
            # 解析tcp
            app_packet, tcp_header = parse_tcp(trans_packet)
            info['src_port'] = tcp_header['Source_Port']
            info['dst_port'] = tcp_header['Destination_Port']
            info['type'] = 'TCP'
            packet_head_json['Transmission Control Protocol'] = tcp_header

        elif ip_header['Protocol'] == 17:
            # 解析udp
            app_packet, udp_header = parse_udp(trans_packet)
            info['src_port'] = udp_header['Source_Port']
            info['dst_port'] = udp_header['Destination_Port']
            info['type'] = 'UDP'
            packet_head_json['User Datagram Protocol'] = udp_header

        elif ip_header['Protocol'] == 1:
            # 解析icmp
            icmp_header = parse_icmp(trans_packet)
            info['type'] = 'ICMP'
            packet_head_json['ICMP'] = icmp_header

        else:
            # 其他类型的协议，未实现
            print("unknown l4-protocol with protocol:", ip_header['Protocol'], 'in ipv4 header')
    elif eth_header['Type'] == '0x0806':
        arp_header = parse_arp(ip_packet)
        info['type'] = 'ARP'
        packet_head_json['ARP'] = arp_header
        # print("[ARP] protocol(", eth_header[2], ") can't parse now")

    elif eth_header['Type'] == '0x86dd':
        parse_ipv6(ip_packet)
        # TODO 更新info中的信息,更新packet——header——json中的信息
        info['type'] = 'IPv6'
        # print("[IPv6] protocol(", eth_header[2], ") can't parse now")
    elif eth_header['Type'] == '0x8864':
        print("[PPPoE] protocol(", eth_header['Type'], ") can't parse now")
    elif eth_header['Type'] == '0x8100':
        print("[802.1Q tag] protocol(", eth_header['Type'], ") can't parse now")
    elif eth_header['Type'] == '0x8847':
        print("[MPLS Label] protocol(", eth_header['Type'], ") can't parse now")
    else:
        # unknown ip protocol
        print("unknown ip protocol with type:", eth_header['Type'])

    return info, packet_head_json


def bytes2mac_addr(addr):
    """将字节流转为MAC地址字符串"""
    return ":".join("%02x" % i for i in addr)


def bytes2uint(data):
    """将字节流转为大尾端无符号整数"""
    return int.from_bytes(data, byteorder='big', signed=False)


def parse_eth(packet):
    """解析链路层头部
    :return: 网络层的数据包和解析过的链路层头部（包含源、目的MAC地址，网络层协议类型）
    """
    # 获取头部字节流
    # ！表示网络序，s表示一个字节
    eth_header = list(unpack("!6s6sH", packet[:14]))
    res = {}
    # 转为可读的MAC地址
    # 目的
    res['Destination'] = bytes2mac_addr(eth_header[0])
    # eth_header[0] = bytes2mac_addr(eth_header[0])
    # 源
    res['Source'] = bytes2mac_addr(eth_header[1])
    # eth_header[1] = bytes2mac_addr(eth_header[1])
    # 转为十六进制的下一层协议类型，需要是字符串
    res['Type'] = "".join("0x%04x" % eth_header[2])
    # eth_header[2] = "".join("0x%04x" % eth_header[2])
    return packet[14:], res


def parse_ipv4(packet):
    """解析网络层头部，类型为ipv4
    :return: 传输层数据包和字典形式的ip层头部信息
    """
    header_info = unpack("!BBHHHBBH4s4s", packet[:20])

    ip_header = {}
    ip_header['Version'] = header_info[0] >> 4
    # 单位是4Bytes
    ip_header['Header_Length'] = header_info[0] & 0x0f
    ip_header['Differentiated_Services_Field'] = header_info[1]
    # 单位是Byte，包括ip头部和数据部分长度
    ip_header['Total_Length'] = header_info[2]
    ip_header['Identification'] = header_info[3]
    ip_header['Flags'] = header_info[4] >> 13
    ip_header['Fragment_Offset'] = header_info[4] & 0x1fff
    ip_header['Time_to_Live'] = header_info[5]
    ip_header['Protocol'] = header_info[6]
    ip_header['Header_Checksum'] = header_info[7]
    ip_header['Source_Address'] = inet_ntoa(header_info[8])
    ip_header['Destination_Address'] = inet_ntoa(header_info[9])
    # 头部没有Option可选部分
    if ip_header['Header_Length'] == 5:
        # 返回下一层数据包和ip头部信息
        return packet[20:], ip_header
    else:
        # TODO 解析Option可选字段
        option = packet[20:ip_header['Header_Length'] * 4]
        return packet[ip_header['Header_Length'] * 4:], ip_header


def parse_ipv6(packet):
    """解析网络层头部，类型为ipv6
    :return: 传输层数据包和字典形式的ip层头部信息
    """
    header_info = unpack("!IHBB16s16s", packet[:40])

    ip_header = {}
    ip_header['Version'] = header_info[0] >> 4
    ip_header['Traffic_Class'] = (header_info[0] >> 20) & 0x0ff
    ip_header['Flow_Label'] = header_info[0] & 0xfffff
    # 单位为字节，包括了ipv6扩展头部
    ip_header['Payload_Length'] = header_info[1]
    # 指代下一个头部类型，可以是传输层头部，也可以是ipv6拓展头部
    # 0     逐跳选线扩展报头
    # 60    目的选项扩展报头
    # 43    路由扩展报头
    # 44    分片扩展报头
    # 51    认证扩展报头
    # 50    封装安全有效载荷扩展报头
    # 58    ICMPv6信息报文扩展报头
    # 59    无下一个扩展报头
    # ref: https://blog.csdn.net/luguifang2011/article/details/81667826
    ip_header['Next_Header'] = header_info[2]
    # ttl
    ip_header['Hop_Limit'] = header_info[3]
    ip_header['Source_Address'] = inet_ntop(AF_INET6, header_info[4])
    ip_header['Destination_Address'] = inet_ntop(AF_INET6, header_info[5])

    if ip_header['Next_Header'] == 17:
        ip_header['Protocol'] = 17
    elif ip_header['Next_Header'] == 6:
        ip_header['Protocol'] = 6
    else:
        print("Can not parse next_header type:(", ip_header['Next_Header'], ") in ipv6 header")

    return packet[40:], ip_header


def parse_tcp(packet):
    """解析传输层头部，类型为tcp
    :return: 传输层payload，字典形式的tcp层头部信息
    """
    header_info = unpack("!HHIIHHHH", packet[:20])

    tcp_header = {}
    tcp_header['Source_Port'] = header_info[0]
    tcp_header['Destination_Port'] = header_info[1]
    tcp_header['Sequence_Number'] = header_info[2]
    tcp_header['Acknowledgement_Number'] = header_info[3]
    # 单位是4Bytes
    tcp_header['Header_Length'] = header_info[4] >> 12
    tcp_header['Flags'] = header_info[4] & 0xfff
    tcp_header['Window'] = header_info[5]
    tcp_header['Checksum'] = header_info[6]
    tcp_header['Urgent_Pointer'] = header_info[7]

    # 头部没有Option可选部分
    if tcp_header['Header_Length'] == 5:
        # 返回下一层数据包和tcp头部信息
        return packet[20:], tcp_header
    else:
        # TODO 解析Option可选字段
        option = packet[20:tcp_header['Header_Length'] * 4]
        return packet[tcp_header['Header_Length'] * 4:], tcp_header


def parse_udp(packet):
    """解析传输层头部，类型为udp
    :return: 传输层的payload，字典形式的udp层头部信息
    """
    header_info = unpack("!HHHH", packet[:8])

    udp_header = {}
    udp_header['Source_Port'] = header_info[0]
    udp_header['Destination_Port'] = header_info[1]
    udp_header['Length'] = header_info[2]
    udp_header['Checksum'] = header_info[3]

    return packet[8:], udp_header


def parse_icmp(packet):
    """解析icmp头部，其位于ip头部的后面
    :return: 字典形式的icmp头部信息
    """
    header_info = unpack("!BBHHH", packet[:8])

    icmp_header = {}
    icmp_header['Type'] = header_info[0]
    icmp_header['Code'] = header_info[1]
    icmp_header['Checksum'] = header_info[2]
    icmp_header['Identifier'] = header_info[3]
    icmp_header['Sequencu_Number'] = header_info[4]

    return icmp_header


def parse_arp(packet):
    """解析icmp头部，其位于mac头部的后面
    :return: 字典形式的arp头部信息
    """
    header_info = unpack("!HHBBH", packet[:8])

    arp_header = {}
    h_type = header_info[0]
    p_type = header_info[1]
    h_size = header_info[2]
    p_size = header_info[3]
    arp_header['Hardware_type'] = h_type
    arp_header['Protocol_type'] = p_type
    arp_header['Hardware_size'] = h_size
    arp_header['Protocol_size'] = p_size
    arp_header['Opcode'] = header_info[4]

    form = "!"
    form += str(h_size) + "s"
    form += str(p_size) + "s"
    form += str(h_size) + "s"
    form += str(p_size) + "s"
    address = unpack(form, packet[8: 8 + (h_size + p_size) * 2])
    if h_type == 1 and p_type == 0x0800:
        # ethernet ipv4
        arp_header['Sender_Hard_address'] = bytes2mac_addr(address[0])
        arp_header['Sender_Prot_address'] = inet_ntoa(address[1])
        arp_header['Target_Hard_address'] = bytes2mac_addr(address[2])
        arp_header['Target_Prot_address'] = inet_ntoa(address[3])
    else:
        # 不确定链路层和ip层使用的协议类型
        arp_header['Sender_Hard_address'] = address[0]
        arp_header['Sender_Prot_address'] = address[1]
        arp_header['Target_Hard_address'] = address[2]
        arp_header['Target_Prot_address'] = address[3]

    return arp_header

# TODO: stp icmpv6
#  DNS FTP SMTP TLS HTTP
