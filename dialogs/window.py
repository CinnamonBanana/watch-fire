from cmath import pi
from PyQt5 import QtGui
from PyQt5.QtWidgets import QMainWindow, QSystemTrayIcon, QAction, QMenu, qApp
from ui.main import Ui_MainWindow

from modules.sniffer import Sniffer
import scapy.all as scapy

import pickle

class MainWindow(QMainWindow):

    settings = {
        'maxLog' : 100,
        'tray': True,
        'autostart': False,
        'adapter': 'Dell Wireless 1705 802.11b|g|n (2.4GHZ)'
    }

    def __init__(self, parent = None):
        super(MainWindow, self).__init__(parent)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.textEdit.setReadOnly(True)
        self.setWindowIcon(QtGui.QIcon("icon.ico"))
        
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
        self.update_settings()

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
                QSystemTrayIcon.Information,
                2000
            )

    def pac_analyse(self, pkt):
        # self.ui.textEdit.insertPlainText(f"Received from {pkt['Ether'].type}\n")
        if pkt['Ether'].type == 2048: ## IPv4 code
            self.ui.textEdit.insertPlainText(f"Received pckt from {pkt['IP'].src}\n")
    
    def receive_msg(self, pkt):
        self.ui.textEdit.insertPlainText(f"Received broadcast from {pkt['Ether'].src}\n")