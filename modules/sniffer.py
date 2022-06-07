import time
import csv
import pickle
import threading

import sklearn
import pandas as pd
import scapy.all as scapy
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import QMessageBox

from modules.utils import *
from inet import *


class Sniffer(QThread):
    framesReceived = pyqtSignal(object)
    broadcastReceived = pyqtSignal(object)
    startFailed = pyqtSignal(object)
    callAlert = pyqtSignal(object)
    updateCSV = pyqtSignal(object)

    def __init__(self, adapter, save = False, parent=None):
        super(Sniffer, self).__init__(parent)
        self.app = parent
        self.adapter = adapter
        self.exiting = False
        self.mac = mymac
        self.border = 0.75
        self.buffer = {}
        self.save = save
        self.fieldnames = ['proto','ports', 'portmin', 'portmax', 'delay', 'count', 'length', 'suspicious']
        if save:
            self.filename = './csv/data.csv'
            try:
                with open(self.filename, 'r', buffering=1) as csvfile:
                    print('file already exists!')
            except:
                with open(self.filename, 'w', newline='') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames)
                    writer.writeheader()

    def __del__(self):
        self.exiting = True
        self.wait()

    def run(self):
        try:
            match self.save:
                case 0:    
                    self.model = pickle.load(open('model', "rb"))
                    self.badmodel = pickle.load(open('badmodel', "rb"))
                case 2:
                    try:
                        self.buffer = pickle.load(open('.buffer', "rb"))
                    except:
                        self.buffer = {}
            scapy.sniff(iface=self.adapter, store=False, prn=self.pktProcess, lfilter=self.isNotOutgoing)
        except Exception as e:
            self.startFailed.emit(f"Cannot access current adapter: {self.adapter}\nError: {e}")

    def pktProcess(self, pkt):
        # print(pkt.show())
        if pkt['Ether'].dst == 'ff:ff:ff:ff:ff:ff':
            if 'Raw' in pkt and not self.save:
                self.broadcastReceived.emit({'src':pkt['IP'].src, 'msg': pkt['Raw'].load})
        else:
            data = self.pkt_info(pkt)
            if not data: return
            if 'UDP' in pkt:
                if pkt['UDP'].dport == 1900: return
            match self.save:
                case 0:
                    pred = self.predictor(data)
                    self.framesReceived.emit({'ip': pkt['IP'].src, 'score':pred})
                case 1:
                    self.collector(pkt['IP'].src, data)
                case 2:
                    self.collector(pkt['IP'].src, data) 
    
    def collector(self, src, data, show = False):
        data['suspicious'] = self.buffer[src]['suspicious']
        if show: print(data)
        if not data['suspicious']:
            # print(f"========\n{src=}\n{data=}")
            with open(self.filename, 'a', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames)
                writer.writerow(data)
            self.updateCSV.emit(None)

    def predictor(self, data):
        df = pd.DataFrame(columns=self.fieldnames[:-1])
        df.loc[0] = list(data.values())
        return self.model.predict(df)[0], self.badmodel.predict(df)[0]

    def pkt_info(self, pkt):
        if all (k not in pkt for k in ('DNS','ARP')):
            ip = pkt['IP'].src
            curtime = time.time()
            if ip not in self.buffer:
                self.buffer[ip] = {}
                self.buffer[ip]['suspicious'] = 1 if self.save == 2 else 0
                if self.save == 2:
                    self.buffer[ip]['suspicious'] = int(self.call_Alert(ip))
            proto = get_proto(pkt['IP'].proto)
            sproto = str(proto)
            if sproto not in self.buffer[ip]:
                self.new_proto(ip, sproto, curtime)
            if curtime-self.buffer[ip][sproto]['start']<=5:
                try:
                    port = pkt[2].dport
                    self.buffer[ip][sproto]['pkt']['ports'] += port
                    min = self.buffer[ip][sproto]['pkt']['portmin'] 
                    max = self.buffer[ip][sproto]['pkt']['portmax']
                    if port < min: self.buffer[ip][sproto]['pkt']['portmin'] = port
                    if port > max: self.buffer[ip][sproto]['pkt']['portmax'] = port
                except:
                    self.buffer[ip][sproto]['pkt']['ports'] += 0
                self.buffer[ip][sproto]['pkt']['delay'] += curtime - self.buffer[ip][sproto]['last']
                self.buffer[ip][sproto]['last'] = curtime
                self.buffer[ip][sproto]['pkt']['count'] += 1
                self.buffer[ip][sproto]['pkt']['length'] += len(list(pkt)[-1])
                return False
            else:
                a = self.buffer[ip].pop(sproto, False)['pkt']
                return get_avg(proto, a)

    def new_proto(self, ip, proto, time):
        self.buffer[ip][proto] = {'start': time, 'last': time, 
                                    'pkt': {
                                        'ports': 0,
                                        'portmin':65535,
                                        'portmax': 0,
                                        'delay': 0,
                                        'count': 0,
                                        'length': 0
                                    }
                                }

    def call_Alert(self, ip):
        thread_name = threading.current_thread().name
        self.app.responses[ip] = None
        self.callAlert.emit(ip)
        while self.app.responses[ip] is None:
            pass
            time.sleep(0.1)
        return self.app.responses[ip]

    def isNotOutgoing(self, pkt):
        if all (k in pkt for k in ('Ether','IP')):
            return pkt['Ether'].src != self.mac

if __name__ == "__main__":
    pass
    # adapter = "Dell Wireless 1705 802.11b|g|n (2.4GHZ)"

    # MYMAC = "b0:10:41:1b:30:79"
    # ANDROID = "a8:9c:ed:75:77:41"

    # def isNotOutgoing(pkt):
    #     return pkt['Ether'].src != MYMAC# and pkt['Ether'].type == 2048
    #     #return pkt['Ether'].src == ANDROID

    # def http_header(pkt):
    #     print(pkt.show())
        
    # scapy.sniff(iface=adapter, store=False, prn=http_header, lfilter=isNotOutgoing)
