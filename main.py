import time
import netifaces
import psutil
from sniffer import mySniffer
from sniffer import sniffer_thread
from queue import Queue


# 获取网卡名称和其ip地址，不包括回环
def get_netcard():
    routingNicName = netifaces.gateways()['default'][netifaces.AF_INET][1]

    # netifaces.interfaces——列举所有的设备名称
    for interface in netifaces.interfaces():
        if interface == routingNicName:
            # netifaces.ifaddresses(interface)——获得设备对应的IP地址
            # AF_LINK表示链路层地址
            # AF_INET表示IPv4地址
            # AF_INET6表示IPv6地址
            try:
                routingNicMacAddr = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
                routingIPAddr = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
            except KeyError:
                pass
    display_format = '%-30s %-20s'
    print(display_format % ("Routing NIC Name:", routingNicName))
    print(display_format % ("Routing IP Address:", routingIPAddr))

    netcard_info = []
    info = psutil.net_if_addrs()
    for k, v in info.items():
        for item in v:
            if item[0] == 2 and not item[1] == '127.0.0.1':
                netcard_info.append((k, item[1]))
    return netcard_info


if __name__ == '__main__':
    # 测试打印网卡信息
    print(get_netcard())

    sniffer = mySniffer()
    sniffer.show_all_ifaces()
    sniffer.create_socket(14)

    # 共享队列，sniffer存储抓到的数据包，parse读取解析
    packet_wait_queue = Queue()
    sniffer_process = sniffer_thread(packet_wait_queue, sniffer)
    sniffer_process.start()
    time.sleep(3)
    sniffer_process.stop()
    print(packet_wait_queue.qsize())

    #TODO: packet_wait_queue保存的是数据包，开始进行解析







