# 仿Wireshark界面的嗅探器设计

使用Python完成的网络数据包嗅探器，使用scapy实现抓包功能，使用tkinter进行了界面设计。

使用的Python库有：tkinter、scapy、struct、threading、socket。

## 支持的功能

*   选择网卡进行实时抓包
*   抓包的停止与重新开始
*   简单的捕获时过滤
*   简单的捕获后过滤
*   保存抓包数据为Pcap文件
*   打开Pcap文件
*   点击包列表标题栏排序数据包
*   点击数据包显示其详细信息和二进制数据
*   追踪DNS流
*   支持解析IPv4、IPv6、ICMP、ARP、UDP、TCP等协议

## 使用方式

安装Python3和所需Python库。

使用命令启动开始界面：

```shell
python main.py
```

## 界面展示

启动界面：

![image-20210509113902017](https://gitee.com/liang_qi/blog-image/raw/master/img/image-20210509113902017.png)

抓包界面：

![image-20210509114205037](https://gitee.com/liang_qi/blog-image/raw/master/img/image-20210509114205037.png)

