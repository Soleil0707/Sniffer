import math
import struct
import tkinter as tk
import tkinter.messagebox
import sniffer as Sniffer
import parse as Parse
from tkinter import ttk, filedialog


def xx():
    tk.messagebox.showinfo('通知', '当前选项的功能暂未实现')


class gui:
    def __init__(self, sniffer, ifaces_list, packet_wait_queue):
        """图形界面创建，传入参数为生成的嗅探器实例和iface网卡列表"""
        self.sniffer = sniffer
        self.ifaces_list = ifaces_list
        self.packet_wait_queue = packet_wait_queue

        self.sniffer_process = None
        self.parse_process = None
        self.packet_list_after_id = None
        self.pcap_file = None

        # 创建主窗口
        self.root = tk.Tk()
        self.root.title('Sniffer')
        # 使窗口屏幕居中
        self.root.geometry('%dx%d' % (self.root.winfo_screenwidth() / 1.3,
                                      self.root.winfo_screenheight() / 1.3))
        # 窗口最大化，只有windows下能用
        # self.root.state('zoomed')
        # 窗口大小可调整
        self.root.resizable(width=True, height=True)
        self.root.update()

        # 创建顶部菜单栏
        self.create_menu()

        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)

        # 启动软件时的界面，上方进行文件操作，下方选择网卡进行抓包
        self.first_panel = tk.Frame(self.root)
        self.first_panel.grid(sticky='NSEW')

        # 上方显示文件界面
        self.first_panel.rowconfigure(0, weight=1)
        self.first_panel.columnconfigure(0, weight=1)
        # 下方显示网卡界面
        self.first_panel.rowconfigure(1, weight=1)
        self.first_panel.columnconfigure(1, weight=1)
        # TODO 创建上方面板,功能为打开pcap文件
        # 创建下方面板
        self.create_ifaces_panel(ifaces_list=ifaces_list)

        self.root.protocol('WM_DELETE_WINDOW', self.exit_all)
        # 进入消息循环
        self.root.mainloop()

    def create_packet_bin_panel(self):
        """创建包的二进制数据预览界面，被start_capture_panel调用"""
        # 包二进制数据界面
        self.packet_bin_info = tk.Frame(self.root, bg='lightgray')
        self.packet_bin_info.pack(side=tk.RIGHT, fill=tk.BOTH, expand=tk.TRUE)

        self.packet_bin_info.update()

        # 用于展示二进制流，禁止编辑
        self.packet_bin = tk.Listbox(self.packet_bin_info, font=('consolas', 10))
        self.packet_bin_Ybar = ttk.Scrollbar(self.packet_bin_info,
                                             orient=tk.VERTICAL,
                                             command=self.packet_bin.yview)
        self.packet_bin_Xbar = ttk.Scrollbar(self.packet_bin_info,
                                             orient=tk.HORIZONTAL,
                                             command=self.packet_bin.xview)
        self.packet_bin.configure(xscrollcommand=self.packet_bin_Xbar.set,
                                  yscrollcommand=self.packet_bin_Ybar.set)

        self.packet_bin_Xbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.packet_bin_Ybar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_bin.pack(side=tk.TOP, fill=tk.BOTH, expand=tk.TRUE)

    def create_packet_header_panel(self):
        """创建左下角的包信息预览面板，被start_capture_panel调用"""
        # 包头信息界面
        self.packet_header_info = tk.Frame(self.root)
        self.packet_header_info.pack(side=tk.LEFT, fill=tk.BOTH, expand=tk.TRUE)

        self.packet_header_info.update()

        self.packet_header = ttk.Treeview(self.packet_header_info, show='tree')
        self.packet_header_Ybar = ttk.Scrollbar(self.packet_header_info,
                                                orient=tk.VERTICAL,
                                                command=self.packet_header.yview)
        self.packet_header_Xbar = ttk.Scrollbar(self.packet_header_info,
                                                orient=tk.HORIZONTAL,
                                                command=self.packet_header.xview)

        self.packet_header.configure(xscrollcommand=self.packet_header_Xbar.set,
                                     yscrollcommand=self.packet_header_Ybar.set)
        # 各控件位置
        self.packet_header_Xbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.packet_header_Ybar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_header.pack(side=tk.TOP, fill=tk.BOTH, expand=tk.TRUE)

    def create_packet_list_panel(self):
        """创建包捕获实时更新面板，被start_capture_panel调用"""
        # 包列表界面
        self.packet_list_frame = tk.Frame(self.root)

        # 将控件放置在主窗口
        self.packet_list_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=tk.TRUE)

        # 更新packet_list_frame的参数
        self.packet_list_frame.update()

        # 定义捕获包的信息显示列表
        self.packet_list = ttk.Treeview(self.packet_list_frame, show='headings',
                                        columns=("1", "2", "3", "4", "5", "6", "7"))
        self.packet_list_Xbar = ttk.Scrollbar(self.packet_list_frame,
                                              orient=tk.HORIZONTAL,
                                              command=self.packet_list.xview)
        self.packet_list_Ybar = ttk.Scrollbar(self.packet_list_frame,
                                              orient=tk.VERTICAL,
                                              command=self.packet_list.yview)

        list_width = 100
        self.packet_list.column("1", width=list_width, anchor='center')
        self.packet_list.column("2", width=list_width, anchor='center')
        self.packet_list.column("3", width=list_width, anchor='center')
        self.packet_list.column("4", width=list_width, anchor='center')
        self.packet_list.column("5", width=list_width, anchor='center')
        self.packet_list.column("6", width=list_width, anchor='center')
        self.packet_list.column("7", width=list_width, anchor='center')

        self.packet_list.heading("1", text='序号')
        self.packet_list.heading("2", text='时间')
        self.packet_list.heading("3", text='源地址')
        self.packet_list.heading("4", text='源端口')
        self.packet_list.heading("5", text='目的地址')
        self.packet_list.heading("6", text='目的端口')
        self.packet_list.heading("7", text='协议类型')

        # 设置包信息显示列表的滚动条
        self.packet_list.configure(xscrollcommand=self.packet_list_Xbar.set,
                                   yscrollcommand=self.packet_list_Ybar.set)
        # 定义包显示列表的各控件位置
        self.packet_list_Xbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.packet_list_Ybar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_list.pack(side=tk.TOP, fill=tk.BOTH, expand=tk.TRUE)

        self.packet_list.bind("<ButtonPress-1>", self.display_packet_info)

    def create_menu(self):
        # 创建菜单栏
        self.menu = tk.Menu(self.root)
        self.menu1 = tk.Menu(self.root)

        # 创建菜单栏的一项，tearoff表示？？
        self.file_menu = tk.Menu(self.menu, tearoff=0)

        # 创建名为文件的菜单选项
        self.menu.add_cascade(label='文件', menu=self.file_menu)

        # 创建文件菜单的子选项（打开），点击时执行command对应的函数
        self.file_menu.add_command(label='打开', command=xx)
        self.file_menu.add_command(label='保存', command=self.save_file)
        self.file_menu.add_command(label='另存为', command=self.save_as)

        self.file_menu.entryconfigure('打开', state=tk.ACTIVE)
        self.file_menu.entryconfigure('保存', state=tk.DISABLED)
        self.file_menu.entryconfigure('另存为', state=tk.DISABLED)

        # 添加分割线
        self.file_menu.add_separator()

        # 创建文件菜单的子选项（退出），点击时执行command对应的函数
        self.file_menu.add_command(label='退出', command=self.exit_all)

        # 创建菜单栏的抓包选项
        self.menu.add_command(label='停止抓包', command=self.stop_capture)
        self.menu.entryconfigure('停止抓包', state=tk.DISABLED)
        self.menu.add_command(label='重新开始抓包', command=self.start_capture)
        self.menu.entryconfigure('重新开始抓包', state=tk.DISABLED)

        # 使菜单显示出来
        self.root.config(menu=self.menu)

    def create_ifaces_panel(self, ifaces_list=None):
        """创建打开界面下方的网卡选择面板"""
        # 设计下方界面
        self.ifaces_choose_frame = tk.Frame(self.first_panel)
        self.ifaces_choose_frame.grid(row=1, columnspan=2, sticky='nsew')

        self.ifaces_choose_frame.update()

        self.iface_list_treeview = ttk.Treeview(self.ifaces_choose_frame, show='headings',
                                                columns=("1", "2", "3", "4", "5"))
        self.iface_list_Xbar = ttk.Scrollbar(self.ifaces_choose_frame,
                                             orient=tk.HORIZONTAL,
                                             command=self.iface_list_treeview.xview)
        self.iface_list_Ybar = ttk.Scrollbar(self.ifaces_choose_frame,
                                             orient=tk.VERTICAL,
                                             command=self.iface_list_treeview.yview)
        ifaces_list_width = 200
        self.iface_list_treeview.column("1", anchor="center", width=ifaces_list_width - 150)
        self.iface_list_treeview.column("2", anchor="center", width=ifaces_list_width)
        self.iface_list_treeview.column("3", anchor="center", width=ifaces_list_width - 100)
        self.iface_list_treeview.column("4", anchor="center", width=ifaces_list_width)
        self.iface_list_treeview.column("5", anchor="center", width=ifaces_list_width - 50)
        self.iface_list_treeview.heading("1", text="索引值")
        self.iface_list_treeview.heading("2", text="名称")
        self.iface_list_treeview.heading("3", text="IPv4地址")
        self.iface_list_treeview.heading("4", text="IPv6地址")
        self.iface_list_treeview.heading("5", text="MAC地址")

        self.iface_list_treeview.configure(xscrollcommand=self.iface_list_Xbar.set,
                                           yscrollcommand=self.iface_list_Ybar.set)

        self.iface_list_Xbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.iface_list_Ybar.pack(side=tk.RIGHT, fill=tk.Y)
        self.iface_list_treeview.pack(side=tk.TOP, expand=tk.TRUE, fill=tk.BOTH)

        # 网卡信息插入treeview中
        for ifaces in ifaces_list[1:]:
            self.iface_list_treeview.insert("", "end", value=ifaces)
        self.iface_list_treeview.update()

        self.iface_list_treeview.bind("<Double-1>", self.switch_capture_panel)

    def switch_capture_panel(self, event):
        """双击选择一个iface，切换到抓包界面开始抓包"""
        item = self.iface_list_treeview.identify('item', event.x, event.y)
        iface = self.iface_list_treeview.item(item, 'values')

        index = int(iface[0])

        # 界面切换至抓包
        if index <= 1:
            tk.messagebox.showwarning("警告", '请选择正确的网卡——索引值大于1（不包含1）')
            return

        self.first_panel.destroy()
        # 进行抓包界面布局
        self.start_capture_panel(iface)

    def start_capture_panel(self, iface):
        """被switch_capture_panel函数调用，开启抓包界面。同时启动抓包和解析包的线程
        传入的参数为网卡信息列表，依次为索引值、名称、ipv4、ipv6、mac地址"""

        # 创建抓包实时更新面板，位于菜单栏下方
        self.create_packet_list_panel()
        # 创建包头信息预览面板，位于左下角
        self.create_packet_header_panel()
        # 创建包的二进制数据预览面板, 位于右下角
        self.create_packet_bin_panel()

        # 进行socket绑定
        self.iface = iface
        self.start_capture()

    def display_packets(self):
        # 确定当前是否有数据包需要display
        if self.parse_process is not None:
            while len(self.parse_process.packet_info) != self.parse_process.packet_display_index:
                info = self.parse_process.packet_info[self.parse_process.packet_display_index]
                self.parse_process.packet_display_index += 1
                self.packet_list.insert("", "end", value=(info['num'], info['time'], info['src_addr'], info['src_port'],
                                                          info['dst_addr'], info['dst_port'], info['type']))
        # 更新时跳转至最后一行
        # self.packet_list.yview_moveto(1)
        # 500ms后再次调用
        self.packet_list.after(500, self.display_packets)

    def stop_capture(self):
        if self.sniffer_process:
            self.sniffer_process.stop()
        if self.parse_process:
            self.parse_process.stop()
        if self.packet_list_after_id:
            # 将抓到的剩余的包全部展示出来再暂停
            self.display_packets()
            self.packet_list.after_cancel(self.packet_list_after_id)

        self.menu.entryconfigure('停止抓包', state=tk.DISABLED)
        self.menu.entryconfigure('重新开始抓包', state=tk.ACTIVE)

        self.file_menu.entryconfigure('打开', state=tk.ACTIVE)
        self.file_menu.entryconfigure('保存', state=tk.ACTIVE)
        self.file_menu.entryconfigure('另存为', state=tk.ACTIVE)

    def start_capture(self):
        self.sniffer.create_socket(int(self.iface[0]))

        # 清空界面（在重新开始抓包时清空原有的抓包记录）
        self.packet_list.delete(*self.packet_list.get_children())
        self.packet_wait_queue.queue.clear()

        self.menu.entryconfigure('停止抓包', state=tk.ACTIVE)
        self.menu.entryconfigure('重新开始抓包', state=tk.DISABLED)

        self.file_menu.entryconfigure('打开', state=tk.DISABLED)
        self.file_menu.entryconfigure('保存', state=tk.DISABLED)
        self.file_menu.entryconfigure('另存为', state=tk.DISABLED)

        # 创建抓包线程
        self.sniffer_process = Sniffer.sniffer_thread(self.packet_wait_queue, self.sniffer)
        # 开启抓包
        self.sniffer_process.start()
        # 创建解析包进程
        self.parse_process = Parse.parse_thread(self.packet_wait_queue)
        # 开启解析
        self.parse_process.start()
        # 调用定时器，每500ms运行一次
        # 记录id，以便于在暂停时使用after_cancel函数
        self.packet_list_after_id = self.packet_list.after(500, self.display_packets)

    def display_packet_info(self, event):
        """点击选中一个包时，调用此函数在下方显示该包的包头信息和二进制数据流"""
        if not self.parse_process:
            return

        item = self.packet_list.identify('item', event.x, event.y)
        packet_info = self.packet_list.item(item, 'values')
        if packet_info == '':
            return
        # list的第一个元素索引为0，所以减1
        index = int(packet_info[0]) - 1
        print(index)

        # 右下方展示packet_bin
        packet = self.parse_process.packet_list[index]
        self.display_packet_bin(packet)

        packet_heads = self.parse_process.packet_head[index]
        self.display_packet_heads(packet_heads)
        # print(packet_heads)

    def display_packet_bin(self, packet):
        """参数为一个完整数据包，调用此函数会将数据包的二进制流输出在右下角"""
        # 清除原有内容
        self.packet_bin.delete(0, tk.END)
        # 按格式显示二进制流
        packet_address = 0
        i = 0
        a = ''
        for bytes_data in packet:
            if i == 0:
                a = "%04x" % packet_address + ':  '
                packet_address += 16
            a += "%02x" % bytes_data
            a += ' '
            i += 1
            if i == 8:
                a += '  '
            if i == 16:
                self.packet_bin.insert(tk.END, a)
                i = 0
        self.packet_bin.insert(tk.END, a)

    def display_packet_heads(self, packet_heads):
        # 清空原有内容
        self.packet_header.delete(*self.packet_header.get_children())

        for layer, header_info in packet_heads.items():
            iid = self.packet_header.insert('', 'end', text=layer)
            for key, value in header_info.items():
                self.packet_header.insert(iid, 'end', text=str(key) + ': ' + str(value))

    def exit_all(self):
        """关闭全部进程，退出程序"""
        # 如果仍在抓包
        if self.sniffer_process is not None and self.sniffer_process.is_set():
            if tk.messagebox.askokcancel('退出程序', '抓包线程仍在运行，确定退出吗?'):
                # 退出
                self.stop_capture()
                self.root.quit()
        # 如果未保存
        else:
            if tk.messagebox.askokcancel('退出程序', '确定退出吗?'):
                # 退出
                self.root.quit()

    def save_file(self):
        """保存文件"""

        # 如果不存在路径则选择保存的位置"""
        if self.pcap_file is None or self.pcap_file.closed():
            self.save_as()
        # 如果已存在路径则保存在路径中，
        else:
            # TODO 将当前抓包数据保存为文件
            a = 1
            self.save_packet_as_pcap()
        # print(self.pcap_file.closed())

    def save_as(self):
        """选择一个位置进行保存"""
        file_path = filedialog.asksaveasfilename(
            filetypes=[('pcap文件', '*.pcap'), ('所有文件', '*.*')]
        )
        if file_path:
            # TODO 将当前抓包数据保存为文件
            a = 1
            self.save_packet_as_pcap(file_path)

    def save_packet_as_pcap(self, file_path):
        """将当前抓包数据保存为文件"""
        # pcap 文件头
        data = struct.pack('!I', int('d4c3b2a1', 16))
        data += struct.pack('!H', int('0200', 16))
        data += struct.pack('!H', int('0400', 16))
        data += struct.pack('!I', int('00000000', 16))
        data += struct.pack('!I', int('00000000', 16))
        data += struct.pack('!I', int('00000400', 16))
        data += struct.pack('!I', int('01000000', 16))

        # 6075287d = 1,618,290,813 换算为Unix时间，精确到秒
        # 000e2077 = 925,815 直接转为ms，小数点后
        packets = self.parse_process.packet_list
        pkt_times = self.parse_process.packet_time

        for index in range(min(len(packets), len(pkt_times))):
            packet, time = packets[index], pkt_times[index]
            time_low, time_high = math.modf(time)
            data += struct.pack('!I', int(time_high))
            data += struct.pack('!I', int(time_low * 10**9))
            # 数据包大小，单位字节
            data += struct.pack('!I', len(packet))
            data += struct.pack('!I', len(packet))
            data += packet

        try:
            f = open(file_path, 'wb')
            f.write(data)
            f.close()
        # except Exception:
        except IOError:
            tk.messagebox.showwarning('保存', '保存文件失败')
