import scapy.all as scapy


class mySniffer:
    def __init__(self):
        self.iface = None
        self.socket = None

    @staticmethod
    def show_all_ifaces():
        """打印所有interface"""
        return scapy.IFACES.show()

    def create_socket(self, index):
        """根据打印的索引确定一个interface，然后创建socket绑定用于抓包"""
        self.iface = scapy.IFACES.dev_from_index(14)
        # TODO 可以和init函数合并
        # 进行绑定，便于抓包
        self.socket = scapy.conf.L2socket(iface=self.iface)

    def get_one_packet(self):
        """ 抓取一个数据包
        调用这个函数前需要使用create_socket创建socket
        返回依次为:链路层数据包类型、数据包数据、时间
        :return: 链路层数据包类型，数据包，时间
        """

        # TODO: 考虑抓包效率，可能会丢包
        # 调用这个函数 抓取一个数据包
        return self.socket.recv_raw()
