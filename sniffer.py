from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from tkinter.ttk import Treeview
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
import threading

event = threading.Event()
ps=list()   # ps为当前数据包展示区的包建立一个全局列表

def timestamp2time(time_stamp):
    delta_ms = str(time_stamp - int(time_stamp))
    time_temp = time.localtime(time_stamp)
    my_time = time.strftime("%Y-%m-%d %H:%M:%S", time_temp)
    my_time += delta_ms[1:8]
    return my_time


class GUI:
    def __init__(self):
        self.root = Tk()
        self.root.title('网络嗅探器')
        self.root.geometry("500x200+1100+150")
        self.interface()

    def interface(self):
        # 添加标签控件
        self.label1 = Label(self.root,text="请选择网卡",font=("黑体",11),fg="black")
        self.label1.pack(padx=10,pady=10)

        # 添加选择框
        values = ['WLAN', '以太网2', '蓝牙网络连接']
        self.combobox = ttk.Combobox(
                    master=self.root, # 父容器
                    height=10,        # 高度：下拉显示的条目数量
                    width=20,         # 宽度
                    state='',         # 设置状态 
                    cursor='arrow',   # 鼠标移动时样式 
                    font=('', 15),    # 字体、字号
                    textvariable='',  # 通过StringVar设置可改变的值
                    values=values,    # 设置下拉框的选项
                )
        self.combobox.pack(padx=10,pady=0)

        # 添加标签控件
        self.label2 = Label(self.root,text="请输入BPF过滤条件",font=("黑体",11),fg="black")
        self.label2.pack(padx=10,pady=10)

        # 添加输入框
        self.entry=Entry(self.root,width=100)
        self.entry.pack(padx=10,pady=0)

        # 添加菜单功能
        self.mainmenu = Menu(self.root)
        self.menuFile = Menu(self.mainmenu) 
        self.mainmenu.add_cascade(label="文件",menu=self.menuFile)
        self.menuFile.add_command(label="打开",command=self.file_open)
        self.menuFile.add_command(label="保存",command=self.file_save)
        self.menuFile.add_command(label="退出",command=self.root.destroy)
        
        self.menuEdit = Menu(self.mainmenu)
        self.mainmenu.add_cascade(label="编辑",menu=self.menuEdit)
        self.menuEdit.add_command(label="清空",command=self.clear_data)
        
        self.menuCap = Menu(self.mainmenu) 
        self.mainmenu.add_cascade(label="捕获",menu=self.menuCap)
        self.menuCap.add_command(label="开始",command=self.start)
        self.menuCap.add_command(label="暂停",command=self.pause)
        self.menuCap.add_command(label="继续",command=self.cont)

        self.root.config(menu=self.mainmenu)

        #添加数据包展示区
        self.packet_tree=Treeview(
            self.root,
            columns=('num','packet_time','src','dst','proto','length','info'),
            show='headings',
            displaycolumns="#all"   
            )
        self.packet_tree.heading('num',text="序号",anchor=W)
        self.packet_tree.column('num', width=70, anchor='w')
        self.packet_tree.heading('packet_time',text="时间",anchor=W)
        self.packet_tree.heading('src',text="源IP/MAC",anchor=W)
        self.packet_tree.heading('dst',text="目的IP/MAC",anchor=W)
        self.packet_tree.heading('proto',text="协议",anchor=W)
        self.packet_tree.heading('length',text="长度",anchor=W)
        self.packet_tree.heading('info',text="数据",anchor=W)
        self.packet_tree.column('info', width=800, anchor='w')
        self.packet_tree.pack(padx=50,pady=30)
        self.packet_tree.bind("<<TreeviewSelect>>",self.callback)

        self.hbar = ttk.Scrollbar(self.root, orient=HORIZONTAL, command=self.packet_tree.xview)
        self.hbar.place(relx=0.033, rely=0.445, relwidth=0.94, relheight=0.015)
        self.packet_tree.configure(xscrollcommand=self.hbar.set) 

        # 添加十六进制展示区文本框
        self.textbox1=Text(self.root,width=190,height=20)
        self.textbox1.pack(padx=50,pady=30)

    def file_open(self):
        file_path = filedialog.askopenfilename()
        fd=open(file_path,"rb")
        reader=PcapReader(fd)
        for v in reader:
            self.packet_display(v)
            ps.append(v)


    def m_event(self):
        '''抓包事件，一直循环'''
        while True:
            packet=sniff(filter=self.filter,count=1,iface=self.iface) 
            event.wait()
            for p in packet:
                self.packet_display(p)
                ps.append(p)


    def packet_display(self,p):
        packet_time= timestamp2time(p.time)
        src = p[Ether].src
        dst = p[Ether].dst
        length = len(p)  
        info = p.summary()

        t = p[Ether].type
        protols_Ether = {0x0800:'IPv4',0x0806:'ARP',0x86dd:'IPv6',0x88cc:'LLDP',0x891D:'TTE'}
        if t in protols_Ether:
            proto = protols_Ether[t]
        else:
            proto = 'Not clear'
      
        #数据包都会有第三层
        if proto == 'IPv4':
            protos_ip = {1: 'ICMP', 2: 'IGMP', 4: 'IP', 6: 'TCP', 8: 'EGP', 9: 'IGP', 17: 'UDP', 41: 'IPv6', 50: 'ESP', 89:'OSPF'}
            src = p[IP].src
            dst = p[IP].dst
            t=p[IP].proto
            if t in protos_ip:
                proto=protos_ip[t]
        
        #数据包可能有第四层
        if TCP in p:
            protos_tcp = {80: 'Http', 443: 'Https', 23: 'Telnet', 21: 'Ftp', 20: 'ftp_data', 22: 'SSH', 25: 'SMTP'}
            sport = p[TCP].sport
            dport = p[TCP].dport
            if sport in protos_tcp:
                proto = protos_tcp[sport]
            elif dport in protos_tcp:
                proto = protos_tcp[dport]
        
        elif UDP in p:
            if p[UDP].sport == 53 or p[UDP].dport == 53:
                proto = 'DNS'

        self.packet_tree.insert("",END,values=(len(self.packet_tree.get_children())+1,packet_time,src,dst,proto,length,info))


    def start(self):
        self.iface=self.combobox.get()
        self.filter=self.entry.get()
        event.set()
        T1 = threading.Thread(target=self.m_event, daemon=True)
        T1.start()


    def pause(self):
        event.clear()


    def cont(self):
        event.set()


    def file_save(self):
        file_path=filedialog.asksaveasfilename(title=u'保存文件')
        wrpcap(file_path, ps) 


    def clear_data(self):
        x=self.packet_tree.get_children()
        for item in x:
            self.packet_tree.delete(item)
        self.textbox1.delete("1.0",END)
        ps.clear()


    def callback(self,event):
        item = self.packet_tree.set(self.packet_tree.focus())
        pos=int(item["num"])
        pkt=ps[pos-1]
        self.textbox1.delete("1.0",END)
        self.textbox1.insert(END, hexdump(pkt, dump=True))


if __name__ == '__main__':
    a = GUI()
    a.root.mainloop()
