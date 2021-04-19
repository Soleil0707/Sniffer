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
        # 两种工作模式，1表示实时捕获数据包，2表示读取打开的pcap文件
        self.mode = 0
        # 记录点击标题排序时是否逆序
        self.reverse = True
        self.after_capture_filter_id = 0

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
        # 创建上方面板,功能为打开pcap文件
        self.create_open_file_panel()
        # 创建下方面板
        self.create_ifaces_panel(ifaces_list=ifaces_list)

        self.root.protocol('WM_DELETE_WINDOW', self.exit_all)
        # 进入消息循环
        self.root.mainloop()

    def create_menu(self):
        # 创建菜单栏
        self.menu = tk.Menu(self.root)

        # 创建菜单栏的抓包选项
        self.menu.add_command(label='另存为', command=self.save_as)
        self.menu.entryconfigure('另存为', state=tk.DISABLED)
        self.menu.add_command(label='停止抓包', command=self.stop_capture)
        self.menu.entryconfigure('停止抓包', state=tk.DISABLED)
        self.menu.add_command(label='重新开始抓包', command=self.start_capture)
        self.menu.entryconfigure('重新开始抓包', state=tk.DISABLED)
        self.menu.add_command(label='退出', command=self.exit_all)
        self.menu.entryconfigure('退出', state=tk.ACTIVE)

        # 使菜单显示出来
        self.root.config(menu=self.menu)

    def create_open_file_panel(self):
        self.open_pcap_frame = tk.Frame(self.first_panel)
        self.open_pcap_frame.grid(row=0, columnspan=2, sticky='nsew')

        label = tk.Label(self.open_pcap_frame, text='打开', font=('楷书', 20), fg='gray')
        button = tk.Button(self.open_pcap_frame, text='选择文件路径', command=self.open_pcap_file)
        label.pack(side=tk.TOP, fill=tk.X)
        button.pack(side=tk.TOP, expand=tk.TRUE)

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

        # # 更新packet_list_frame的参数
        # self.packet_list_frame.update()

        # 定义捕获包的信息显示列表
        self.packet_list_treeview = ttk.Treeview(self.packet_list_frame, show='headings',
                                                 columns=("1", "2", "3", "4", "5", "6", "7"))
        self.packet_list_Xbar = ttk.Scrollbar(self.packet_list_frame,
                                              orient=tk.HORIZONTAL,
                                              command=self.packet_list_treeview.xview)
        self.packet_list_Ybar = ttk.Scrollbar(self.packet_list_frame,
                                              orient=tk.VERTICAL,
                                              command=self.packet_list_treeview.yview)

        list_width = 100
        self.packet_list_treeview.column("1", width=list_width, anchor='center')
        self.packet_list_treeview.column("2", width=list_width, anchor='center')
        self.packet_list_treeview.column("3", width=list_width, anchor='center')
        self.packet_list_treeview.column("4", width=list_width, anchor='center')
        self.packet_list_treeview.column("5", width=list_width, anchor='center')
        self.packet_list_treeview.column("6", width=list_width, anchor='center')
        self.packet_list_treeview.column("7", width=list_width, anchor='center')

        self.packet_list_treeview.heading("1", text='序号')
        self.packet_list_treeview.heading("2", text='时间')
        self.packet_list_treeview.heading("3", text='源地址')
        self.packet_list_treeview.heading("4", text='源端口')
        self.packet_list_treeview.heading("5", text='目的地址')
        self.packet_list_treeview.heading("6", text='目的端口')
        self.packet_list_treeview.heading("7", text='协议类型')

        # 添加点击标题排序的功能
        for col in ['1', '2', '3', '4', '5', '6', '7']:
            self.packet_list_treeview.heading(col,
                                              command=lambda _col=col: self.treeview_sort(self.packet_list_treeview,
                                                                                          _col, self.reverse))

        # 设置包信息显示列表的滚动条
        self.packet_list_treeview.configure(xscrollcommand=self.packet_list_Xbar.set,
                                            yscrollcommand=self.packet_list_Ybar.set)

        label_filter = tk.Label(self.packet_list_frame, text='  过滤器：   ')
        self.after_capture_filter_str = tk.StringVar()
        self.after_capture_filter = tk.Entry(self.packet_list_frame, textvariable=self.after_capture_filter_str)
        self.filter_button = tk.Button(self.packet_list_frame, text='  点击过滤 ', command=self.after_capture_filter_packet)

        # 定义包显示列表的各控件位置
        self.packet_list_Xbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.packet_list_Ybar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_list_treeview.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=tk.TRUE)

        label_filter.pack(side=tk.LEFT)
        self.filter_button.pack(side=tk.RIGHT)
        self.after_capture_filter.pack(side=tk.LEFT, fill=tk.X, expand=tk.TRUE)

        self.packet_list_treeview.bind("<ButtonPress-1>", self.display_packet_info)

    def create_ifaces_panel(self, ifaces_list=None):
        """创建打开界面下方的网卡选择面板"""
        # 设计下方界面
        self.ifaces_choose_frame = tk.Frame(self.first_panel)
        self.ifaces_choose_frame.grid(row=1, columnspan=2, sticky='nsew')

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

        label = tk.Label(self.ifaces_choose_frame, text='捕获', font=('楷书', 20), fg='gray')
        label_filter = tk.Label(self.ifaces_choose_frame, text='   过滤器：  ')
        self.filter_str = tk.StringVar()
        self.filter = tk.Entry(self.ifaces_choose_frame, textvariable=self.filter_str)

        label.pack(side=tk.TOP, fill=tk.X)
        self.iface_list_Xbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.iface_list_Ybar.pack(side=tk.RIGHT, fill=tk.Y)
        self.iface_list_treeview.pack(side=tk.BOTTOM, expand=tk.TRUE, fill=tk.BOTH)
        label_filter.pack(side=tk.LEFT)
        self.filter.pack(side=tk.TOP, fill=tk.X)

        # 网卡信息插入treeview中
        for ifaces in ifaces_list[1:]:
            self.iface_list_treeview.insert("", "end", value=ifaces)
        self.iface_list_treeview.update()

        self.iface_list_treeview.bind("<Double-1>", self.switch_capture_panel)

    def switch_capture_panel(self, event):
        """双击选择一个iface，切换到抓包界面开始抓包"""

        # 解析过滤器
        self.filter_id = self.parse_filter(self.filter_str.get())
        if self.filter_id < 0:
            tk.messagebox.showwarning('过滤器', '无法解析过滤器，请重新输入')
            return

        item = self.iface_list_treeview.identify('item', event.x, event.y)
        iface = self.iface_list_treeview.item(item, 'values')

        index = int(iface[0])

        # 界面切换至抓包
        if index <= 1:
            tk.messagebox.showwarning("警告", '请选择正确的网卡——索引值大于1（不包含1）')
            return

        # 进行socket绑定
        self.iface = iface

        self.mode = 1
        # 进行抓包界面布局
        self.start_capture_panel()
        # 开启抓包线程
        self.start_capture()

    def start_capture_panel(self):
        """被switch_capture_panel函数调用，开启抓包界面。同时启动抓包和解析包的线程
        传入的参数为网卡信息列表，依次为索引值、名称、ipv4、ipv6、mac地址"""

        self.first_panel.destroy()

        # 创建抓包实时更新面板，位于菜单栏下方
        self.create_packet_list_panel()
        # 创建包头信息预览面板，位于左下角
        self.create_packet_header_panel()
        # 创建包的二进制数据预览面板, 位于右下角
        self.create_packet_bin_panel()

    def start_capture(self):
        self.menu.entryconfigure('停止抓包', state=tk.ACTIVE)
        self.menu.entryconfigure('重新开始抓包', state=tk.DISABLED)
        self.menu.entryconfigure('另存为', state=tk.DISABLED)

        # 清空界面（在重新开始抓包时清空原有的抓包记录）
        self.packet_list_treeview.delete(*self.packet_list_treeview.get_children())

        self.sniffer.create_socket(int(self.iface[0]))

        self.packet_wait_queue.queue.clear()
        # 创建抓包线程
        self.sniffer_process = Sniffer.sniffer_thread(self.packet_wait_queue, self.sniffer)
        # 开启抓包
        self.sniffer_process.start()
        # 创建解析包进程
        self.parse_process = Parse.parse_thread(self.packet_wait_queue, self.filter_id, self.filter_str.get())
        # 开启解析
        self.parse_process.start()
        # 调用定时器，每500ms运行一次
        # 记录id，以便于在暂停时使用after_cancel函数
        self.packet_list_after_id = self.packet_list_treeview.after(500, self.display_packets)

    def stop_capture(self):
        if self.sniffer_process:
            self.sniffer_process.stop()
        if self.parse_process:
            self.parse_process.stop()
        if self.packet_list_after_id:
            # 将抓到的剩余的包全部展示出来再暂停
            self.display_packets()
            self.packet_list_treeview.after_cancel(self.packet_list_after_id)

        self.menu.entryconfigure('停止抓包', state=tk.DISABLED)
        self.menu.entryconfigure('重新开始抓包', state=tk.ACTIVE)
        self.menu.entryconfigure('另存为', state=tk.ACTIVE)

    def display_packets(self):
        # 确定当前是否有数据包需要display
        if self.parse_process is not None:
            while len(self.parse_process.packet_info) != self.parse_process.packet_display_index:
                info = self.parse_process.packet_info[self.parse_process.packet_display_index]
                packet_head = self.parse_process.packet_head[self.parse_process.packet_display_index]
                if Parse.filter_packet(self.after_capture_filter_id, packet_head, self.after_capture_filter_str.get()):
                    self.packet_list_treeview.insert("", "end", value=(info['num'], info['time'], info['src_addr'],
                                                                       info['src_port'], info['dst_addr'],
                                                                       info['dst_port'], info['type']))
                self.parse_process.packet_display_index += 1
        # 更新时跳转至最后一行
        # self.packet_list.yview_moveto(1)
        # 500ms后再次调用
        self.packet_list_treeview.after(500, self.display_packets)

    def display_packet_info(self, event):
        """点击选中一个包时，调用此函数在下方显示该包的包头信息和二进制数据流"""
        if self.mode == 1 and not self.parse_process:
            return

        item = self.packet_list_treeview.identify('item', event.x, event.y)
        packet_info = self.packet_list_treeview.item(item, 'values')
        if packet_info == '':
            return
        # list的第一个元素索引为0，所以包的序号减1为索引
        index = int(packet_info[0]) - 1
        print(index)

        # 右下方展示packet_bin
        if self.mode == 1:
            packet = self.parse_process.packet_list[index]
            packet_heads = self.parse_process.packet_head[index]
        else:
            packet = self.packet_list[index]
            packet_heads = self.packet_head[index]

        self.display_packet_bin(packet)
        self.display_packet_heads(packet_heads)

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

    def save_as(self):
        """另存为，选择一个位置进行保存"""
        file_path = filedialog.asksaveasfilename(
            filetypes=[('pcap文件', '*.pcap'), ('所有文件', '*.*')]
        )
        if file_path:
            # 将当前抓包数据保存为文件
            # 区分两种模式
            if self.mode == 1:
                # 6075287d = 1,618,290,813 换算为Unix时间，精确到秒
                # 000e2077 = 925,815 直接转为ms，小数点后
                self.save_packet_as_pcap(file_path, packets=self.parse_process.packet_list,
                                         pkt_times=self.parse_process.packet_time)
            else:
                self.save_packet_as_pcap(file_path, pcap_head=self.pcap_head,
                                         packets=self.packet_list, pkt_times=self.packet_time)

    def save_packet_as_pcap(self, file_path, pcap_head=None, packets=None, pkt_times=None):
        """将当前抓包数据保存为文件"""
        # pcap 文件头
        if pcap_head is None:
            data = struct.pack('!I', int('d4c3b2a1', 16))
            data += struct.pack('!H', int('0200', 16))
            data += struct.pack('!H', int('0400', 16))
            data += struct.pack('!I', int('00000000', 16))
            data += struct.pack('!I', int('00000000', 16))
            data += struct.pack('!I', int('00000400', 16))
            data += struct.pack('!I', int('01000000', 16))
        else:
            data = pcap_head

        for index in range(min(len(packets), len(pkt_times))):
            packet = packets[index]
            time_high, time_low = pkt_times[index]
            data += struct.pack('<I', time_high)
            data += struct.pack('<I', time_low)
            # 数据包大小，单位字节
            # 转换为小端
            data += struct.pack('<I', len(packet))
            data += struct.pack('<I', len(packet))
            data += packet

        try:
            f = open(file_path, 'wb')
            f.write(data)
            f.close()
        # except Exception:
        except IOError:
            tk.messagebox.showwarning('保存', '保存文件失败')
            return
        tk.messagebox.showinfo('保存', '保存成功')

    def open_pcap_file(self):
        file_path = tk.filedialog.askopenfilename(
            filetypes=[('pcap文件', '*.pcap')]
        )
        # 打开成功
        if file_path:
            if file_path.split('.')[-1] != 'pcap':
                tk.messagebox.showwarning('打开', '只能解析pcap格式的文件!')
                return

            self.mode = 2
            self.pcap_head, self.packet_time, self.packet_list, self.packet_info, self.packet_head \
                = Parse.parse_pcap_file(file_path)

            self.start_capture_panel()

            self.menu.entryconfigure('停止抓包', state=tk.DISABLED)
            self.menu.entryconfigure('重新开始抓包', state=tk.DISABLED)
            self.menu.entryconfigure('另存为', state=tk.ACTIVE)

            index = 0
            while len(self.packet_info) != index:
                info = self.packet_info[index]
                index += 1
                self.packet_list_treeview.insert('', 'end', value=(info['num'], info['time'], info['src_addr'],
                                                                   info['src_port'], info['dst_addr'],
                                                                   info['dst_port'], info['type']))

    def treeview_sort(self, treeview, col, reverse):
        """点击标题时调用此函数进行排序, 传入参数为 treeview 列名 排列方式"""
        items = [(treeview.set(k, col), k) for k in treeview.get_children('')]
        # print(treeview.get_children(''))

        def sort_accord_int(item):
            num, col_num = item
            return -1 if num == '-' else int(num)

        if col == '1' or col == '4' or col == '6':
            items.sort(reverse=reverse, key=sort_accord_int)  # 排序方式
        else:
            items.sort(reverse=reverse)  # 排序方式

        for index, (val, k) in enumerate(items):  # 根据排序后索引移动
            treeview.move(k, '', index)
        self.reverse = not reverse
        treeview.heading(col, command=lambda: self.treeview_sort(treeview, col, self.reverse))  # 重写标题，使之成为再点倒序的标题

    def parse_filter(self, filter_str):
        """解析输入过滤器的字符串是否符合语法，符合则返回true"""
        if filter_str == '':
            return 0

        # 去除所有空格
        filter_str = filter_str.replace(' ', '')

        if filter_str == 'tcp':
            return 1
        elif filter_str == 'udp':
            return 2
        else:
            filter_str = filter_str.split('==')
            # ip==1.1.1.1
            if filter_str[0] == 'ip':
                return 3
            # port==23
            elif filter_str[0] == 'port':
                return 4
            # src.ip==1.1.1.1
            elif filter_str[0] == 'src.ip':
                return 5
            # dst.ip==1.1.1.1
            elif filter_str[0] == 'dst.ip':
                return 6
            # src.port==12
            elif filter_str[0] == 'src.port':
                return 7
            # dst.port==12
            elif filter_str[0] == 'dst.port':
                return 8
            # tcp.port==12
            elif filter_str[0] == 'tcp.port':
                return 9
            # udp.port==12
            elif filter_str[0] == 'udp.port':
                return 10
            # tcp.stream==12
            elif filter_str[0] == 'tcp.stream':
                return 11
            # udp.stream==12
            elif filter_str[0] == 'udp.stream':
                return 12
        # 使用ip ip==1.1.1.1 elif re.match('ip==(([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])\.){3}([01]{0,1}\d{0,
        # 1}\d|2[0-4]\d|25[0-5])', filter_str): 使用端口号过滤 port==12 elif re.match('port==^(6553[0-5]|655[0-2][0-9]|65[
        # 0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9])$', filter_str): elif re.match('(
        # src|dst).ip==(([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])\.){3}([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])',
        # filter_str): elif re.match('(src|dst|tcp|udp).port==(?:[1-6][0-5]{0,2}?[0-3]?[0-5]?|[1-5][0-9]{0,4})$',
        # filter_str): elif re.match('(tcp|udp).stream\s*==\s*\d*', filter_str): 更高级的过滤 src.ip==1.1.1.1 dst.port==23
        # tcp.stream==1 udp.port==44
        return -1

    def after_capture_filter_packet(self):
        """抓包后进行过滤"""
        filter_str = self.after_capture_filter_str.get()

        # 解析过滤器
        self.after_capture_filter_id = self.parse_filter(filter_str)
        if self.after_capture_filter_id < 0:
            tk.messagebox.showwarning('过滤器', '无法解析过滤器，请重新输入')
            return

        self.packet_list_treeview.delete(*self.packet_list_treeview.get_children())

        if self.mode == 1:
            self.parse_process.packet_display_index = 0
            self.display_packets()
        else:
            index = 0
            while len(self.packet_info) != index:
                info = self.packet_info[index]
                packet_head = self.packet_head[index]
                if Parse.filter_packet(self.after_capture_filter_id, packet_head, filter_str):
                    self.packet_list_treeview.insert('', 'end', value=(info['num'], info['time'], info['src_addr'],
                                                                       info['src_port'], info['dst_addr'],
                                                                       info['dst_port'], info['type']))
                index += 1

