# -*- coding: utf-8 -*-

"""GUI window with buisness logic."""

import ast
import logging
import pickle
import csv
import os
from datetime import datetime

from PyQt5 import QtGui
from PyQt5.QtCore import Qt, QSettings, QAbstractTableModel
from PyQt5.QtWidgets import QMainWindow, QMessageBox, QSystemTrayIcon, QAction, QMenu, qApp, QHeaderView
from scipy import rand

from modules.db import Database
from modules.learn import Learner
from modules.models import TableModel, CSVModel
from modules.ruleadder import Ruler
from modules.sender import Sender
from modules.sniffer import Sniffer
from modules.utils import data_msg
from inet import *
from ui.main import Ui_MainWindow

class MainWindow(QMainWindow):

    settings = {
        'maxLog': 100,
        'tray': False,
        'remember': True,
        'autostart': False,
        'adapter': '',
        'learning': 0,
        'last_learn': 0,
        'save_buff': False
    }

    devs = [
        '',
        'wlp6s0',
        'Dell Wireless 1705 802.11b|g|n (2.4GHZ)'
    ]

    learn_types = [
        'Everything is safe',
        'Connection confirmation'
    ]

    learn_sched = [
        'Never',
        'Every month',
        'Every 2 months',
        'Every 6 months',
        'Every year'
    ]

    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.textEdit.setReadOnly(True)
        self.setWindowIcon(QtGui.QIcon("icon.ico"))
        self.ui.logoLabel.setPixmap(QtGui.QPixmap("./res/inactive.png"))
        self.db = Database()
        self.minScore = 5
        self.maxScore = 10
        self.server = serverip
        self.token = 'None'
        self.ruler = Ruler()

        logging.basicConfig(filename='watchfire.log',
                            filemode='a',
                            format='%(asctime)s - %(message)s',
                            level=logging.INFO)

        # Tray setup
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

        # Settings setup
        self.ui.logLines.setRange(0, 10000)
        self.ui.devList.currentIndexChanged.connect(
            lambda x: self.show_settings(True))
        self.ui.checkAStart.stateChanged.connect(
            lambda x: self.show_settings(True))
        self.ui.checkTray.stateChanged.connect(
            lambda x: self.show_settings(True))
        self.ui.logLines.valueChanged.connect(
            lambda x: self.show_settings(True))
        self.ui.checkBuff.stateChanged.connect(
            lambda x: self.show_settings(True))
        self.ui.saveSettings.clicked.connect(lambda x: self.set_settings(True))
        self.ui.discardSettings.clicked.connect(
            lambda x: self.set_settings(False))

        try:
            with open('.config', 'rb') as f:
                self.settings = pickle.load(f)
        except:
            with open('.config', 'wb') as f:
                pickle.dump(self.settings, f)

        self.update_settings()
        self.update_login()

        # Learning setup
        self.ui.learnCheck.stateChanged.connect(self.update_login)
        self.ui.learnTypeBox.addItems(self.learn_types)
        self.ui.learnScheduleBox.addItems(self.learn_sched)
        self.ui.learnScheduleBox.currentIndexChanged.connect(lambda x: self.set_learn())
        self.ui.learnButton.clicked.connect(self.learn)
        self.ui.progressLearn.setHidden(True)
        self.responses = {}

        # Init sniffer thread
        self.ui.pushButton.clicked.connect(self.start)
        self.send = None
        self.thread = None

        # Setting up host tables
        self.ui.tabWidget.currentChanged.connect(self.update_hosts)
        self.ui.tableHosts.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.ui.tableBlocked.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.ui.tableCSV.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        try:
            with open('.login', 'rb') as f:
                cred = pickle.load(f)
                self.ui.userEdit.setText(cred['usr'])
                self.ui.pwdEdit.setText(cred['pwd'])
                self.ui.rememberCheck.setChecked(True)
        except:
            pass

    def update_login(self):
        if self.ui.learnCheck.isChecked():
            self.ui.learnTypeBox.setEnabled(True)
            self.ui.userEdit.setEnabled(False)
            self.ui.pwdEdit.setEnabled(False)
            self.ui.rememberCheck.setEnabled(False)
        else:
            self.ui.learnTypeBox.setEnabled(False)
            self.ui.learnTypeBox.setCurrentIndex(0)
            self.ui.userEdit.setEnabled(True)
            self.ui.pwdEdit.setEnabled(True)
            self.ui.rememberCheck.setEnabled(True)

    def update_settings(self):
        self.ui.devList.setCurrentText(self.settings['adapter'])
        self.ui.logLines.setValue(self.settings['maxLog'])
        self.ui.checkTray.setChecked(self.settings['tray'])
        self.ui.checkAStart.setChecked(self.settings['autostart'])
        self.ui.checkBuff.setChecked(self.settings['save_buff'])
        self.ui.textEdit.setMaximumBlockCount(self.settings['maxLog'])
        self.ui.devList.addItems(self.devs)
        self.show_settings(False)

    def set_learn(self):
        self.settings['learning'] = self.ui.learnScheduleBox.currentIndex()
        with open('.config', 'wb') as f:
                pickle.dump(self.settings, f)

    def set_settings(self, new):
        if new:
            self.settings['adapter'] = self.ui.devList.currentText()
            self.settings['tray'] = self.ui.checkTray.isChecked()
            self.settings['autostart'] = self.ui.checkAStart.isChecked()
            self.settings['save_buff'] = self.ui.checkBuff.isChecked()
            self.settings['maxLog'] = self.ui.logLines.value()
            self.ui.textEdit.setMaximumBlockCount(self.settings['maxLog'])
            with open('.config', 'wb') as f:
                pickle.dump(self.settings, f)
        else:
            self.ui.devList.setCurrentText(self.settings['adapter'])
            self.ui.logLines.setValue(self.settings['maxLog'])
            self.ui.checkTray.setChecked(self.settings['tray'])
            self.ui.checkAStart.setChecked(self.settings['autostart'])
            self.ui.checkBuff.setChecked(self.settings['save_buff'])
        self.show_settings(False)

    def show_settings(self, show):
        self.ui.saveSettings.setVisible(show)
        self.ui.discardSettings.setVisible(show)

    def sys_msg(self, msg):
        self.tray_icon.showMessage(
            "Watch-Fire", msg,
            QtGui.QIcon("icon.ico"),
            2000
        )

    def closeEvent(self, event):
        if self.settings['tray']:
            event.ignore()
            self.hide()
            self.sys_msg("Application was minimized to Tray")

    def pac_analyse(self, data):
        ip = data['ip']
        score = data['score'][0]
        badscore = data['score'][1]
        #print(f"=======\n{ip=}\n{score=}\n{badscore=}")
        self.add_host(ip)
        borders = {
            'GOOD': [-0.1, 0.2],
            'ICMP': [2720, 2790],
        }
        bad = [0.85, 1.1]
        if all (not k[0]<score<k[1] for k in (borders.values())):
            status = self.add_badscore(ip, add=5 if bad[0]<=badscore<=bad[1] else 1)
            if status not in ['G', 'RO']:
                self.send.add_msg(data_msg(ip=ip, status=status, token=self.token))
    
    def receive_msg(self, data):
        try:
            msg = ast.literal_eval(data['msg'].decode('UTF-8'))
            src = data['src']
            if 'type' in msg:
                if not self.validate_msg(src, msg): return
                match msg['type']:
                    case 'Alert':
                        self.add_badscore(msg['ip'])
                    case 'Token':
                        pass
                        #print(f'TOKEN PROCESS!\n{msg=}')
                    case _:
                        return

        except Exception as e:
            pass

    def validate_msg(self, src, msg):
        if src == self.server:
            if msg['tmstmp']<=float(rec[-1]): return False
            return True
        rec = self.db.get_host(src)
        if rec:
            if msg['token'] != rec[4]: return False
            if msg['tmstmp']<=float(rec[-1]): return False
            return True

    def token_update(self, ip, data):
        self.db.edit_host(ip, data)

    def update_hosts(self, i):
        match i:
            case 1:
                data = self.db.get_hosts(blocked=False)
                header = ["Status", "Hostname", "IP", "Changed"]
                self.model = TableModel(header, data)
                self.ui.tableHosts.setModel(self.model)
            case 2:
                data = self.db.get_hosts(blocked=True)
                header = ["Status", "Hostname", "IP", "Changed"]
                self.model = TableModel(header, data)
                self.ui.tableBlocked.setModel(self.model)
            case 3:
                self.ui.learnScheduleBox.setCurrentIndex(self.settings['learning'])
                header = ['Protocol','Avg Ports', 'Port min', 'Port max', 'Delay', 'Count', 'Length', 'Suspicious']
                try:
                    with open('./csv/data.csv') as File:
                        reader = csv.reader(File)
                        data = list(reader)[1:]
                        self.model = CSVModel(header, data)
                except:
                    self.model = CSVModel(header, [])
                self.ui.tableCSV.setModel(self.model)

            case _:
                return

    def start(self):
        # send credentials to server
        if self.ui.devList.currentText() == None: return
        mode = int(self.ui.learnCheck.isChecked()) + self.ui.learnTypeBox.currentIndex()
        self.thread = Sniffer(str(self.settings['adapter']), save=mode, parent=self)
        self.thread.startFailed.connect(self.start_error)
        self.ui.pushButton.setText("Stop")
        self.ui.pushButton.clicked.disconnect(self.start)
        self.ui.pushButton.clicked.connect(self.stop)
        self.log("System started.")
        self.sys_msg("System started")

        if self.ui.learnCheck.isChecked():
            self.thread.callAlert.connect(self.alert)
            self.thread.updateCSV.connect(self.update_csv)
            self.ui.logoLabel.setPixmap(QtGui.QPixmap("./res/learn.png"))
        else:
            self.ui.logoLabel.setPixmap(QtGui.QPixmap("./res/logo.png"))
            self.thread.framesReceived.connect(self.pac_analyse)
            self.thread.broadcastReceived.connect(self.receive_msg)
            self.send = Sender()
            if self.ui.rememberCheck.isChecked():
                self.login_save()
            self.send.start()

        self.ui.learnCheck.setEnabled(False)
        self.ui.learnTypeBox.setEnabled(False)
        self.thread.start()

    def stop(self):
        self.thread.terminate()
        if self.ui.learnCheck.isChecked():
            self.ui.learnTypeBox.setEnabled(True)
            if self.settings['save_buff'] and self.ui.learnTypeBox.currentIndex():
                with open('.buffer', 'wb') as f:
                    pickle.dump(self.thread.buffer, f)
        else:
            self.send.terminate()
            self.send = None
        self.thread = None
        self.log("System terminated.")
        self.sys_msg("System terminated.")
        self.ui.logoLabel.setPixmap(QtGui.QPixmap("./res/inactive.png"))
        self.ui.pushButton.setText("Start")
        self.ui.pushButton.clicked.disconnect(self.stop)
        self.ui.pushButton.clicked.connect(self.start)
        self.ui.learnCheck.setEnabled(True)

    def start_error(self, msg):
        QMessageBox.critical(self,
                             self.tr("ERROR!"),
                             self.tr(msg))
        self.log(msg)
        self.stop()

    def login_save(self):
        data = {
            'usr': self.ui.userEdit.text(),
            'pwd': self.ui.pwdEdit.text()
        }
        with open('.login', 'wb') as f:
            pickle.dump(data, f)

    def log(self, msg):
        logging.info(msg)
        self.ui.textEdit.insertPlainText(
            f'{datetime.now().strftime("%d-%m-%y %H:%M:%S")} - {msg}\n')

    def update_csv(self, _=None):
        self.update_hosts(self.ui.tabWidget.currentIndex())

    def add_host(self, ip):
        if ip not in self.db.get_ips():
            data = {'name': "Unknown",
                    'ip': ip,
                    'status': "G",
                    'badscore': '0',
                    'token': "None"}
            self.db.add_host(data)
            self.update_hosts(self.ui.tabWidget.currentIndex())
            self.log(f"Added {data['ip']} host")

    def add_badscore(self, ip, add=1):
        if ip not in self.db.get_ips(blocked=True):
            if not self.db.get_host(ip):
                self.add_host(ip)
            row = self.db.get_host(ip)
            scr = int(row[3])+add
            if scr >= self.maxScore:
                self.change_host_status(ip, 'R', scr)
                self.log(f"{ip} was successfully blocked!")
                self.block_ip()
                status = 'R'
            elif  self.minScore<= scr <self.maxScore:
                self.change_host_status(ip, 'Y', scr)
                status = 'Y'
            else:
                self.change_host_status(ip, 'G', scr)
                status = 'G'
            return status
        else:
            return 'RO'

    def change_host_status(self, ip, status, score):
        self.db.edit_host(ip, {'status': status, 'badscore': score})
        self.update_hosts(self.ui.tabWidget.currentIndex())
        self.log(f"{ip} status changed to {status}{score}")

    def block_ip(self):
        try:
            self.ruler.block_ips(self.db.get_ips(blocked=True))
        except:
            pass
        print(f"IPS TO BLOCK {self.db.get_ips(blocked=True)}")

    def alert(self, ip):
        ret = QMessageBox.warning(self, 'Suspicious activity!', f"Unknown traffic type from IP \n{ip}\nIs the connection trusted?",
                                  QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        self.responses[ip] = ret != QMessageBox.Yes
        return ret != QMessageBox.Yes

    def learn(self):
        if self.thread is None:
            self.ui.progressLearn.setHidden(False)
            self.learner = Learner()
            self.learner.endLearn.connect(self.end_learn)
            self.learner.progressAdd.connect(self.pb_update)
            self.learner.start()
        else:
            QMessageBox.critical(self,
                             self.tr("ERROR!"),
                             self.tr('Cannot learn, while scan is active!'))
    def end_learn(self):
        self.learner.terminate()
        self.learner = None
        os.rename('./csv/data.csv', './csv/data.csv.backup')
        self.update_csv()

    def pb_update(self, prog):
        self.ui.progressLearn.setValue(prog)