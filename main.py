import time
from sniffer import mySniffer
from sniffer import sniffer_thread
from queue import Queue
from parse import *
from gui import *


if __name__ == '__main__':
    # 创建嗅探器，并绑定指定网卡
    sniffer = mySniffer()
    # 共享队列，sniffer存储抓到的数据包，parse读取解析
    packet_wait_queue = Queue()

    # 获取所有网卡信息
    ifaces_str = sniffer.show_all_ifaces(print_res=False)
    ifaces_str = ifaces_str.split('\n')
    ifaces_list = list()
    for iface in ifaces_str:
        iface_column = list(filter(None, iface.split('  ')))
        for _ in iface_column:
            _ = _.strip()
        ifaces_list.append(iface_column)

    gui = gui(sniffer, ifaces_list, packet_wait_queue)
    """解析包和gui界面的关联：
        整个包的信息——打印二进制流（list）
        包头解析出来的信息——展示在左下角（json）
        包重要信息——展示在包列表中（list）
        使用包序号作为索引去定位每个包的各个信息
    """
    # TODO list:
    #  选择包，展示包的信息
    #  添加打开文件功能
    #  添加filter
    #  开始界面的继续改进
    #  包排序功能
    #  包解析应用层，识别流
    #  共享变量的锁问题
    # 创建嗅探器线程，进行包的捕获
    # sniffer_process = sniffer_thread(packet_wait_queue, sniffer)
    # sniffer_process.start()
    # time.sleep(1)
    # sniffer_process.stop()
    # print(packet_wait_queue.qsize())

    # packet_wait_queue保存的是数据包，开始进行解析
    # l2_type, l2_packet, time = packet_wait_queue.get()

    # parse_pacp_file('test.pcap')
