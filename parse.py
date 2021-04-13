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
    ip_header_info = unpack("!BBHHHBBH4s4s", ip_header)

    ip_header = {}
    ip_header['Version'] = ip_header_info[0] >> 4
    # 单位是4Bytes
    ip_header['Header Length'] = ip_header_info[0] & 0x0f
    ip_header['Differentiated Services Field'] = ip_header_info[1]
    # 单位是Byte，包括ip头部和数据部分长度
    ip_header['Total Length'] = ip_header_info[2]
    ip_header['Identification'] = ip_header_info[3]
    ip_header['Flags'] = ip_header_info[4] >> 13
    ip_header['Fragment Offset'] = ip_header_info[4] & 0x1fff
    ip_header['Time to Live'] = ip_header_info[5]
    ip_header['Protocol'] = ip_header_info[6]
    ip_header['Header Checksum'] = ip_header_info[7]
    ip_header['Source Address'] = inet_ntoa(ip_header_info[8])
    ip_header['Destination Address'] = inet_ntoa(ip_header_info[9])
    # 头部没有Option可选部分
    if ip_header['Header Length'] == 5:
        # 返回下一层数据包和ip头部信息
        return packet[20:], ip_header
    else:
        # TODO 解析Option可选字段
        option = packet[20:ip_header['Header Length']*4]
        return packet[ip_header['Header Length']*4:], ip_header
