from socket import *
from struct import *

"""
B   8bit
H   16bit
I   32bit
"""


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
    eth_header = packet[:14]
    # ！表示网络序，s表示一个字节
    eth_header = list(unpack("!6s6sH", eth_header))
    # 转为可读的MAC地址
    eth_header[0] = bytes2mac_addr(eth_header[0])
    eth_header[1] = bytes2mac_addr(eth_header[1])
    # 转为十六进制的下一层协议类型，需要是字符串
    eth_header[2] = "".join("0x%04x" % eth_header[2])
    return packet[14:], eth_header


def parse_ipv4(packet):
    """解析网络层头部，类型为ipv4
    :return:
    """
    ip_header = packet[:20]
    ip_header = unpack("!BBHHHBBHII", ip_header)
    print(bytes2uint(ip_header[0]))
