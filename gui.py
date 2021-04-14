import tkinter as tk
from tkinter import ttk


def xx():
    return


class gui:
    def __init__(self, ifaces_list=None):
        # 创建主窗口
        self.root = tk.Tk()
        self.root.title('Sniffer')
        # 使窗口屏幕居中
        self.root.geometry('%dx%d' % (self.root.winfo_screenwidth() / 1.5,
                                      self.root.winfo_screenheight() / 1.5))
        # 窗口最大化，只有windows下能用
        # self.root.state('zoomed')
        # 窗口大小可调整
        self.root.resizable(width=True, height=True)
        self.root.update()

        # TODO 添加网卡选择界面
        # 上方显示文件界面
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)
        # 下方显示网卡界面
        self.root.rowconfigure(1, weight=1)
        self.root.columnconfigure(1, weight=1)
        # 创建下方面板
        self.create_ifaces_panel(ifaces_list=ifaces_list)

        # 进入消息循环
        self.root.mainloop()

        #############################
        # 此处开启抓包界面
        # 配置每个grid区域的权重，等分成四个区域
        self.root.rowconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=3)
        self.root.columnconfigure(0, weight=1)
        self.root.columnconfigure(1, weight=1)

        # self.winH = self.root.winfo_height()
        # self.winW = self.root.winfo_width()

        # 创建顶部菜单栏
        self.create_menu()
        # 创建抓包实时更新面板，位于菜单栏下方
        self.create_packet_list_panel()
        # 创建包头信息预览面板，位于左下角
        self.create_packet_header_panel()
        # 创建包的二进制数据预览面板, 位于右下角
        self.create_packet_bin_panel()

        # TODO 将数据包插入并保存
        for _ in range(100):
            self.packet_list.insert("", "end", value=(_, str(_) + '2', str(_) + '3',
                                                      str(_) + '4', str(_) + '5',
                                                      str(_) + '6', str(_) + '7'))
        # # 定时更新
        # self.packet_list.after()
        # # 更新时显示最后一行的内容
        # self.packet_list.yview_moveto(1)
        self.packet_list.update()

        # 进入消息循环
        self.root.mainloop()

    def create_packet_bin_panel(self):
        """创建包的二进制数据预览界面"""
        # 包二进制数据界面
        self.packet_bin_info = tk.Frame(self.root, bg='lightgray')
        # packet_info_frame.pack(anchor='s', fill=tk.X, side='bottom')
        self.packet_bin_info.grid(row=1, column=1, padx=5, pady=5, sticky='NSEW')
        # text TODO 使用哪种控件还不确定

    def create_packet_header_panel(self):
        """创建左下角的包信息预览面板"""
        # 包头信息界面
        self.packet_header_info = tk.Frame(self.root, bg='lightgray')
        self.packet_header_info.grid(row=1, padx=5, pady=5, sticky='NSEW')

        self.packet_header_info.update()

        # treeview
        # TODO 在点击时更新内容
        self.packet_header = ttk.Treeview(self.packet_header_info)
        # TODO 无法拖动
        self.packet_header_Ybar = ttk.Scrollbar(self.packet_header_info,
                                                orient=tk.VERTICAL,
                                                command=self.packet_header.yview())
        self.packet_header_Xbar = ttk.Scrollbar(self.packet_header_info,
                                                orient=tk.HORIZONTAL,
                                                command=self.packet_header.xview())

        self.packet_header.configure(xscrollcommand=self.packet_header_Xbar.set,
                                     yscrollcommand=self.packet_header_Ybar.set)
        # 各控件位置
        self.packet_header.grid(row=0, column=0, sticky="nsew")
        self.packet_header_Ybar.grid(row=0, column=1, sticky="ns")
        self.packet_header_Xbar.grid(row=1, columnspan=2, sticky="ew")

    def create_packet_list_panel(self):
        """创建包捕获实时更新面板"""
        # 包列表界面
        self.packet_list_frame = tk.Frame(self.root)

        # 将控件放置在主窗口
        self.packet_list_frame.grid(row=0, columnspan=2, sticky='NSEW')

        self.packet_list_frame.columnconfigure(0, weight=5)
        self.packet_list_frame.rowconfigure(0, weight=5)

        # 更新packet_list_frame的参数
        self.packet_list_frame.update()

        # 定义捕获包的信息显示列表
        self.packet_list = ttk.Treeview(self.packet_list_frame, show='headings',
                                        columns=("1", "2", "3", "4", "5", "6", "7"))
        self.packet_list_Xbar = ttk.Scrollbar(self.packet_list_frame,
                                              orient=tk.HORIZONTAL,
                                              command=self.packet_list.xview())
        self.packet_list_Ybar = ttk.Scrollbar(self.packet_list_frame,
                                              orient=tk.VERTICAL,
                                              command=self.packet_list.yview())

        list_width = 200
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
        # TODO 无法使用鼠标进行拖动
        self.packet_list.configure(xscrollcommand=self.packet_list_Xbar.set,
                                   yscrollcommand=self.packet_list_Ybar.set)
        # 定义包显示列表的各控件位置
        self.packet_list.grid(row=0, column=0, sticky="nsew")
        self.packet_list_Ybar.grid(row=0, column=1, sticky="ns")
        self.packet_list_Xbar.grid(row=1, columnspan=2, sticky="ew")

    def create_menu(self):
        # 创建菜单栏
        menu = tk.Menu(self.root)
        # 创建菜单栏的一项，tearoff表示？？
        file_menu = tk.Menu(menu, tearoff=0)
        # 创建名为文件的菜单选项
        menu.add_cascade(label='文件', menu=file_menu)
        # 创建文件菜单的子选项（打开），点击时执行command对应的函数
        file_menu.add_command(label='打开', command=xx)
        file_menu.add_command(label='打开最近', command=xx)
        # 添加分割线
        file_menu.add_separator()
        # 创建文件菜单的子选项（退出），点击时执行command对应的函数
        file_menu.add_command(label='退出', command=self.root.quit)
        # 使菜单显示出来
        self.root.config(menu=menu)

    def create_ifaces_panel(self, ifaces_list=None):
        """创建打开界面下方的网卡选择面板"""
        # 设计下方界面
        self.ifaces_choose_frame = tk.Frame(self.root)
        self.ifaces_choose_frame.grid(row=1, columnspan=2, sticky='nsew')

        # 保证后面的treeview能够填充整个界面
        self.ifaces_choose_frame.rowconfigure(0, weight=1)
        self.ifaces_choose_frame.columnconfigure(0, weight=1)

        self.ifaces_choose_frame.update()

        self.iface_list = ttk.Treeview(self.ifaces_choose_frame, show='headings',
                                       columns=("1", "2", "3", "4", "5"))
        self.iface_list_Xbar = ttk.Scrollbar(self.ifaces_choose_frame,
                                             orient=tk.HORIZONTAL,
                                             command=self.iface_list.xview())
        self.iface_list_Ybar = ttk.Scrollbar(self.ifaces_choose_frame,
                                             orient=tk.VERTICAL,
                                             command=self.iface_list.yview())
        ifaces_list_width = 200
        self.iface_list.column("1", anchor="center", width=ifaces_list_width - 150)
        self.iface_list.column("2", anchor="center", width=ifaces_list_width)
        self.iface_list.column("3", anchor="center", width=ifaces_list_width - 100)
        self.iface_list.column("4", anchor="center", width=ifaces_list_width)
        self.iface_list.column("5", anchor="center", width=ifaces_list_width - 50)
        self.iface_list.heading("1", text="索引值")
        self.iface_list.heading("2", text="名称")
        self.iface_list.heading("3", text="IPv4地址")
        self.iface_list.heading("4", text="IPv6地址")
        self.iface_list.heading("5", text="MAC地址")
        # fixme 无法使用鼠标进行拖动
        self.iface_list.configure(xscrollcommand=self.iface_list_Xbar.set,
                                  yscrollcommand=self.iface_list_Ybar.set)
        self.iface_list.grid(row=0, column=0, sticky="nsew")
        self.iface_list_Ybar.grid(row=0, column=1, sticky="ns")
        self.iface_list_Xbar.grid(row=1, columnspan=2, sticky="ew")
        # 网卡信息插入treeview中
        for ifaces in ifaces_list[1:]:
            self.iface_list.insert("", "end", value=ifaces)
        self.iface_list.update()
