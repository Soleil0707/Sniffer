from socket import *
from struct import *

"""
B   8bit
H   16bit
I   32bit
"""


def parse_pacp_file(filename):
    pcap = open(filename, 'rb')
    pcap_header = pcap.read(24)

    pkt_header = pcap.read(16)
    time1, time2, capLen, pktLen = unpack("IIII", pkt_header)
    l2_packet = pcap.read(pktLen)
    parse_a_packet(l2_packet)


def parse_a_packet(packet):
    # 解析数据包的链路层
    ip_packet, eth_header = parse_eth(packet)

    if eth_header[2] == '0x0800':
        trans_packet, ip_header = parse_ipv4(ip_packet)

        if ip_header['Protocol'] == 6:
            # 解析tcp
            app_packet, tcp_header = parse_tcp(trans_packet)
        elif ip_header['Protocol'] == 17:
            # 解析udp
            app_packet, udp_header = parse_udp(trans_packet)
        elif ip_header['Protocol'] == 1:
            # 解析icmp
            icmp_header = parse_icmp(trans_packet)
        else:
            # 其他类型的协议，未实现
            print("unknown l4-protocol with protocol:", ip_header['Protocol'], 'in ipv4 header')
    elif eth_header[2] == '0x0806':
        arp_header = parse_arp(ip_packet)
        # print("[ARP] protocol(", eth_header[2], ") can't parse now")
    elif eth_header[2] == '0x86dd':
        parse_ipv6(ip_packet)
        # print("[IPv6] protocol(", eth_header[2], ") can't parse now")
    elif eth_header[2] == '0x8864':
        print("[PPPoE] protocol(", eth_header[2], ") can't parse now")
    elif eth_header[2] == '0x8100':
        print("[802.1Q tag] protocol(", eth_header[2], ") can't parse now")
    elif eth_header[2] == '0x8847':
        print("[MPLS Label] protocol(", eth_header[2], ") can't parse now")
    else:
        # unknown ip protocol
        print("unknown ip protocol with type:", eth_header[2])


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
    # 转为可读的MAC地址
    eth_header[0] = bytes2mac_addr(eth_header[0])
    eth_header[1] = bytes2mac_addr(eth_header[1])
    # 转为十六进制的下一层协议类型，需要是字符串
    eth_header[2] = "".join("0x%04x" % eth_header[2])
    return packet[14:], eth_header


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