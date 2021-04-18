import scapy.all as scapy
import threading


class sniffer_thread(threading.Thread):
    """ 自定义抓包线程类，相比于threading增加了pause、resume、stop的功能
    并且对run函数做了修改，run会循环执行，每次捕获一个数据包
    """
    def __init__(self, packet_queue, sniffer):
        super(sniffer_thread, self).__init__()
        self.packet_queue = packet_queue
        self.sniffer = sniffer
        self.__flag = threading.Event()     # 用于暂停线程的标识
        self.__flag.set()       # 设置为True
        self.__running = threading.Event()      # 用于停止线程的标识
        self.__running.set()      # 将running设置为True

    def run(self):
        while self.__running.isSet():
            self.__flag.wait()      # 为True时立即返回, 为False时阻塞直到内部的标识位为True后返回
            l2_type, l2_packet, time = self.sniffer.get_one_packet()
            # 网络流量不大时，数据包不多，recv_raw可能返回None
            if l2_packet is not None:
                self.packet_queue.put((l2_type, l2_packet, time))
                # print("get a packet")

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

    def is_set(self):
        return self.__running.isSet()


class mySniffer:
    def __init__(self):
        self.iface = None
        self.socket = None

    @staticmethod
    def show_all_ifaces(print_res=True):
        """打印所有interface"""
        return scapy.IFACES.show(print_result=print_res)

    def create_socket(self, index):
        """根据打印的索引确定一个interface，然后创建socket绑定用于抓包"""
        if index < 0:
            return False
        self.iface = scapy.IFACES.dev_from_index(index)
        # 进行绑定，便于抓包
        # scapy.conf.iface.setmonitor(True)
        self.socket = scapy.conf.L2socket(iface=self.iface)
        return True

    def get_one_packet(self):
        """ 抓取一个数据包
        调用这个函数前需要使用create_socket创建socket
        返回依次为:链路层数据包类型、数据包数据、时间
        :return: 链路层数据包类型，数据包，时间
        """
        # 调用这个函数 抓取一个数据包
        return self.socket.recv_raw()
