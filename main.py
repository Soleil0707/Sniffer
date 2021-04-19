from sniffer import mySniffer
from queue import Queue
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

    # 开启图形界面
    gui = gui(sniffer, ifaces_list, packet_wait_queue)
    # TODO list:
    #  包解析应用层
    #  识别流（创建控件时需要添加列，排序时需要判断列）
    #  共享变量的锁问题
