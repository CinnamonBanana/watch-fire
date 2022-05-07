import tkinter  as tk 
from tkinter import *
from tkinter import ttk
from pystray import MenuItem as item
import pystray
from PIL import Image
from utils.db import DBConnect

class Window:

    colors = {
        'Y':'#FCFC99',
        'G':'#79DE79',
        'R':'#FB6962'
    }

    def __init__(self, trayable=False) -> None:
        self.root = tk.Tk()
        self.root.title("Watch-Fire")
        self.root.geometry("800x600")
        self.root.iconbitmap("icon.ico")
        self.main_window()
        if trayable:
            self.root.protocol('WM_DELETE_WINDOW', self.withdraw_window)
        
    def hosts(self):
        self.host_tab = ttk.Frame(self.tabControl)
        self.vscroll = Scrollbar(self.host_tab)
        self.vscroll.pack(side=RIGHT, fill=Y)

        self.host_table = ttk.Treeview(self.host_tab, yscrollcommand=self.vscroll.set)

        self.vscroll.config(command=self.host_table.yview)

        self.host_table['columns'] = ('status', 'name', 'ip', 'last_edit')

        head_en = {'ip':'IP', 'name':'Name', 'status':'Status', 'last_edit':'Last edit'}

        # format our column
        self.host_table.column("#0", width=0,  stretch=NO)
        for col in self.host_table['columns']:
            self.host_table.column(col,anchor=CENTER, width=80)
            self.host_table.heading(col,text=head_en[col],anchor=CENTER)
        wfdb = DBConnect()
        r_set = wfdb.get_hosts()
        for key, value in self.colors.items():
            self.host_table.tag_configure(tagname=key, background=value)
        for i, host in enumerate(r_set): 
            self.host_table.insert(parent='',index='end', tag=host[0], iid=i,text='', values=host)

        self.host_table.pack(expand=1, fill=tk.BOTH)

    def blocked(self):
        self.blocked_tab = ttk.Frame(self.tabControl)
        self.vscroll = Scrollbar(self.blocked_tab)
        self.vscroll.pack(side=RIGHT, fill=Y)

        self.blocked_table = ttk.Treeview(self.blocked_tab, yscrollcommand=self.vscroll.set)

        self.vscroll.config(command=self.blocked_table.yview)

        self.blocked_table['columns'] = ('status', 'name', 'ip', 'last_edit')

        head_en = {'ip':'IP', 'name':'Name', 'status':'Status', 'last_edit':'Last edit'}

        # format our column
        self.blocked_table.column("#0", width=0,  stretch=NO)
        for col in self.blocked_table['columns']:
            self.blocked_table.column(col,anchor=CENTER, width=80)
            self.blocked_table.heading(col,text=head_en[col],anchor=CENTER)
        wfdb = DBConnect()
        r_set = wfdb.get_hosts(blocked=True)

        for key, value in self.colors.items():
            self.blocked_table.tag_configure(tagname=key, background=value)

        for i, host in enumerate(r_set): 
            self.blocked_table.insert(parent='',index='end', tag=host[0], iid=i,text='', values=host)

        self.blocked_table.pack(expand=1, fill=tk.BOTH)

    def main_window(self):
        self.tabControl = ttk.Notebook(self.root)

        self.hosts()
        self.blocked()

        self.tabControl.add(self.host_tab, text ='All hosts')
        self.tabControl.add(self.blocked_tab, text ='Blocked hosts')
        self.tabControl.pack(expand = 1, fill ="both") 
    
    def quit_window(self, icon, item):
        icon.stop()
        self.root.destroy()

    def show_window(self, icon, item):
        icon.stop()
        self.root.after(0, self.root.deiconify)

    def withdraw_window(self):  
        self.root.withdraw()
        image = Image.open("icon.ico")
        menu = (item('Show', self.show_window), item('Quit', self.quit_window))
        icon = pystray.Icon("name", image, "Watch-Fire", menu)
        icon.run()

    def start(self):
        self.root.mainloop()

if __name__ == "__main__":
    a = Window()
    a.start()












  

  

  
