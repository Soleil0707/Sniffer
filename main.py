import netifaces
import psutil


# 获取网卡名称和其ip地址，不包括回环
def get_netcard():
    netcard_info = []
    info = psutil.net_if_addrs()
    for k, v in info.items():
        for item in v:
            if item[0] == 2 and not item[1] == '127.0.0.1':
                netcard_info.append((k, item[1]))
    return netcard_info


if __name__ == '__main__':
    routingGateway = netifaces.gateways()['default'][netifaces.AF_INET][0]
    routingNicName = netifaces.gateways()['default'][netifaces.AF_INET][1]

    for interface in netifaces.interfaces():
        if interface == routingNicName:
            # print netifaces.ifaddresses(interface)
            routingNicMacAddr = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
            try:
                routingIPAddr = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
                # TODO(Guodong Ding) Note: On Windows, netmask maybe give a wrong result in 'netifaces' module.
                routingIPNetmask = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['netmask']
            except KeyError:
                pass
    display_format = '%-30s %-20s'
    print(display_format % ("Routing Gateway:", routingGateway))
    print(display_format % ("Routing NIC Name:", routingNicName))
    print(display_format % ("Routing NIC MAC Address:", routingNicMacAddr))
    print(display_format % ("Routing IP Address:", routingIPAddr))
    print(display_format % ("Routing IP Netmask:", routingIPNetmask))

    print(get_netcard())






