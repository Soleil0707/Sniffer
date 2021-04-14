import time
import netifaces
import psutil
from sniffer import mySniffer
from sniffer import sniffer_thread
from queue import Queue
from parse import *
from gui import *


if __name__ == '__main__':
    gui = gui()
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

    # parse_pacp_file('test.pcap')
