import time
import netifaces
import psutil
from sniffer import mySniffer
from sniffer import sniffer_thread
from queue import Queue
from parse import *


# 获取网卡名称和其ip地址，不包括回环
# def get_netcard():
#     routingNicName = netifaces.gateways()['default'][netifaces.AF_INET][1]
#
#     # netifaces.interfaces——列举所有的设备名称
#     for interface in netifaces.interfaces():
#         if interface == routingNicName:
#             # netifaces.ifaddresses(interface)——获得设备对应的IP地址
#             # AF_LINK表示链路层地址
#             # AF_INET表示IPv4地址
#             # AF_INET6表示IPv6地址
#             try:
#                 routingNicMacAddr = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
#                 routingIPAddr = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
#             except KeyError:
#                 pass
#     display_format = '%-30s %-20s'
#     print(display_format % ("Routing NIC Name:", routingNicName))
#     print(display_format % ("Routing IP Address:", routingIPAddr))
#
#     netcard_info = []
#     info = psutil.net_if_addrs()
#     for k, v in info.items():
#         for item in v:
#             if item[0] == 2 and not item[1] == '127.0.0.1':
#                 netcard_info.append((k, item[1]))
#     return netcard_info


if __name__ == '__main__':
    # 测试打印网卡信息
    # print(get_netcard())

    # 创建嗅探器，并绑定指定网卡
    # sniffer = mySniffer()
    # sniffer.show_all_ifaces()
    # sniffer.create_socket(18)

    # 共享队列，sniffer存储抓到的数据包，parse读取解析
    # packet_wait_queue = Queue()

    # 创建嗅探器线程，进行包的捕获
    # sniffer_process = sniffer_thread(packet_wait_queue, sniffer)
    # sniffer_process.start()
    # time.sleep(1)
    # sniffer_process.stop()
    # print(packet_wait_queue.qsize())

    # packet_wait_queue保存的是数据包，开始进行解析
    # l2_type, l2_packet, time = packet_wait_queue.get()

    pcap = open('test.pcap', 'rb')
    pcap_header = pcap.read(24)

    pkt_header = pcap.read(16)
    time1, time2, capLen, pktLen = unpack("IIII", pkt_header)
    l2_packet = pcap.read(pktLen)

    # 解析数据包的链路层
    l3_packet, l2_header = parse_eth(l2_packet)

    if l2_header[2] == '0x0800':
        l4_packet, l3_header = parse_ipv4(l3_packet)
        # TODO 进一步解析TCP和UDP
    elif l2_header[2] == '0x0806':
        # TODO: parse arp
        parse_ipv6(l3_packet)
    # elif eth_header[2] == '0x86dd':
    #     # TODO: parse ipv6
    else:
        # unknown ip protocol
        print("unknown ip protocol with type:", l2_header[2])
