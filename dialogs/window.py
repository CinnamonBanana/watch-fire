from PyQt5 import QtGui
from PyQt5.QtWidgets import QMainWindow, QMessageBox, QSystemTrayIcon, QAction, QMenu, qApp, QHeaderView
from PyQt5.QtCore import Qt, QSettings

from ui.main import Ui_MainWindow
from modules.models import TableModel
from modules.sniffer import Sniffer
from modules.db import Database

import pickle, sys, logging

class MainWindow(QMainWindow):

    settings = {
        'maxLog' : 100,
        'tray': True,
        'autostart': False,
        #'adapter': ''
        'adapter': 'Dell Wireless 1705 802.11b|g|n (2.4GHZ)'
    }

    def __init__(self, parent = None):
        super(MainWindow, self).__init__(parent)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.textEdit.setReadOnly(True)
        self.setWindowIcon(QtGui.QIcon("icon.ico"))
        self.db = Database()
        
        logging.basicConfig(filename='watchfire.log', filemode='a',format='%(asctime)s - %(message)s', level=logging.INFO)

        ## Tray setup
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QtGui.QIcon("icon.ico"))
        show_action = QAction("Show", self)
        quit_action = QAction("Exit", self)
        hide_action = QAction("Hide", self)
        show_action.triggered.connect(self.show)
        hide_action.triggered.connect(self.hide)
        quit_action.triggered.connect(qApp.quit)
        tray_menu = QMenu()
        tray_menu.addAction(show_action)
        tray_menu.addAction(hide_action)
        tray_menu.addAction(quit_action)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        
        ## Settings setup
        self.ui.logLines.setRange(0, 10000)
        self.ui.checkAStart.stateChanged.connect(lambda x: self.show_settings(True))
        self.ui.checkTray.stateChanged.connect(lambda x: self.show_settings(True))
        self.ui.logLines.valueChanged.connect(lambda x: self.show_settings(True))
        self.ui.saveSettings.clicked.connect(lambda x: self.set_settings(True))
        self.ui.discardSettings.clicked.connect(lambda x: self.set_settings(False))

        try:
            with open('.config', 'rb') as f:
                self.settings = pickle.load(f)
        except:
            with open('.config', 'wb') as f:       
                pickle.dump(self.settings, f)
        
        RUN_PATH = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        self.autostart = QSettings(RUN_PATH, QSettings.NativeFormat)

        self.update_settings()

        ## Setting up host tables
        self.ui.tabWidget.currentChanged.connect(self.update_hosts)
        self.ui.tableHosts.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.ui.tableBlocked.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        ## Start sniffer thread
        self.thread = Sniffer(str(self.settings['adapter']))
        self.thread.framesReceived.connect(self.pac_analyse)
        self.thread.broadcastReceived.connect(self.receive_msg)
        self.thread.start()

    def update_settings(self):
        self.ui.logLines.setValue(self.settings['maxLog'])
        self.ui.checkTray.setChecked(self.settings['tray'])
        self.ui.checkAStart.setChecked(self.settings['autostart'])
        self.ui.textEdit.setMaximumBlockCount(self.settings['maxLog'])
        self.show_settings(False)

    def set_settings(self, new):
        if new:
            self.settings['tray'] = self.ui.checkTray.isChecked()
            self.settings['autostart'] = self.ui.checkAStart.isChecked()
            self.settings['maxLog'] = self.ui.logLines.value()
            self.ui.textEdit.setMaximumBlockCount(self.settings['maxLog'])
            with open('.config', 'wb') as f:       
                pickle.dump(self.settings, f)
        else:
            self.ui.logLines.setValue(self.settings['maxLog'])
            self.ui.checkTray.setChecked(self.settings['tray'])
            self.ui.checkAStart.setChecked(self.settings['autostart'])
        if self.ui.checkAStart.isChecked():
            self.autostart.setValue("MainWindow",sys.argv[0])
        else:
            self.autostart.remove("MainWindow")
        self.show_settings(False)

    def show_settings(self, show):
        self.ui.saveSettings.setVisible(show)
        self.ui.discardSettings.setVisible(show)

    def closeEvent(self, event):
        if self.settings['tray']:
            event.ignore()
            self.hide()
            self.tray_icon.showMessage(
                "Watch-Fire",
                "Application was minimized to Tray",
                QtGui.QIcon("icon.ico"),
                2000
            )

    def pac_analyse(self, pkt):
        # self.ui.textEdit.insertPlainText(f"Received from {pkt['Ether'].type}\n")
        if pkt['Ether'].type == 2048: ## IPv4 code
            self.add_host(pkt)
            pass
    
    def receive_msg(self, pkt):
        #self.log(f"Received broadcast from {pkt['Ether'].src}\n")
        if pkt['Ether'].type ==2048:
            pass
    
    def update_hosts(self, i):
        if i>1: return
        data = self.db.get_hosts(blocked=i)
        header = ["Status", "Hostname", "IP", "Changed"]
        self.model = TableModel(header, data)
        if i:
            self.ui.tableBlocked.setModel(self.model)
        else:
            self.ui.tableHosts.setModel(self.model)

    def log(self, msg):
        logging.info(msg)
        self.ui.textEdit.insertPlainText(f'{msg}\n')
    
    def add_host(self, pkt):
        if pkt['IP'].src not in self.db.get_ips():
            data = {'name':"NewPC", 
            'ip':pkt['IP'].src, 
            'status':"G", 
            'badscore':'0', 
            'token':"testtoken"}
            self.db.add_host(data)
            self.update_hosts(self.ui.tabWidget.currentIndex())
            self.log(f"Added {data['ip']} host")

    def add_badscore(self, ip):
        if ip not in self.db.get_ips(blocked=True):
            print(self.db.get_host(ip))
        

    def change_host_status(self, ip, status):
        self.db.edit_host(ip, {'status': status})
        self.log(f"{ip} status changed to {status}")