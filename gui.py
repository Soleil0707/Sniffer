import tkinter as tk
from tkinter import ttk


def xx():
    return


class gui:
    def __init__(self):
        # 创建主窗口
        self.root = tk.Tk()
        self.root.title('Sniffer')
        # 使窗口屏幕居中
        self.root.geometry('%dx%d' % (self.root.winfo_screenwidth()/1.5, self.root.winfo_screenheight()/1.5))
        # 窗口最大化，只有windows下能用
        # self.root.state('zoomed')
        # 窗口大小可调整
        self.root.resizable(width=True, height=True)
        self.root.update()

        self.root.rowconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)
        self.root.columnconfigure(0, weight=1)
        self.root.columnconfigure(1, weight=1)

        self.winH = self.root.winfo_height()
        self.winW = self.root.winfo_width()

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

        # 包列表界面
        packet_list_frame = tk.Frame(self.root, bg='lightgray')
        # 将控件放置在主窗口
        # packet_list_frame.pack(anchor='n', fill=tk.X, side='top')
        packet_list_frame.grid(row=0, columnspan=2, padx=5, pady=5, sticky='NSEW')
        packet_list_frame.update()
        # ttk treeview

        # 包头信息界面
        packet_header_info = tk.Frame(self.root, bg='lightgray')
        a = packet_list_frame.winfo_width()
        packet_header_info.grid(row=1, padx=5, pady=5, sticky='NSEW')
        # checkbutton

        # 包二进制数据界面
        packet_bin_info = tk.Frame(self.root, bg='lightgray')
        # packet_info_frame.pack(anchor='s', fill=tk.X, side='bottom')
        packet_bin_info.grid(row=1, column=1, padx=5, pady=5, sticky='NSEW')
        # text

        # 进入消息循环
        self.root.mainloop()
