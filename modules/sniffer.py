import time
import csv
import pickle

import sklearn
import pandas as pd
import scapy.all as scapy
from PyQt5.QtCore import QThread, pyqtSignal

from modules.utils import *


class Sniffer(QThread):
    framesReceived = pyqtSignal(object)
    broadcastReceived = pyqtSignal(object)
    startFailed = pyqtSignal(object)

    def __init__(self, adapter, parent=None):
        super(Sniffer, self).__init__(parent)
        self.adapter = adapter
        self.exiting = False
        self.mac = "b0:10:41:1b:30:79"
        self.border = 0.75
        self.buffer = {}
        self.fieldnames = ['proto','ports', 'portmin', 'portmax', 'delay', 'count', 'length']

    def __del__(self):
        self.exiting = True
        self.wait()

    def run(self):
        try:
            self.model = pickle.load(open('model', "rb"))
            self.badmodel = pickle.load(open('badmodel', "rb"))
            scapy.sniff(iface=self.adapter, store=False, prn=self.pktProcess, lfilter=self.isNotOutgoing)
        except Exception as e:
            self.startFailed.emit(f"Cannot access current adapter: {self.adapter}\nError: {e}")

    def pktProcess(self, pkt):
        # print(pkt.show())
        if pkt['Ether'].dst == 'ff:ff:ff:ff:ff:ff':
            if 'Raw' in pkt:
                self.broadcastReceived.emit({'src':pkt['IP'].src, 'msg': pkt['Raw'].load})
        else:
            data = self.pkt_info(pkt)
            if not data: return
            if 'UDP' in pkt:
                if pkt['UDP'].dport == 1900: return
            pred = self.predictor(data)
            self.framesReceived.emit({'ip': pkt['IP'].src, 'score':pred})

    def predictor(self, data):
        df = pd.DataFrame(columns=self.fieldnames)
        df.loc[0] = list(data.values())
        return self.model.predict(df)[0], self.badmodel.predict(df)[0]

    def pkt_info(self, pkt):
        if all (k not in pkt for k in ('DNS','ARP')):
            ip = pkt['IP'].src
            curtime = time.time()
            if ip not in self.buffer:
                self.buffer[ip] = {}
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

    def isNotOutgoing(self, pkt):
        if all (k in pkt for k in ('Ether','IP')):
            return (pkt['Ether'].src != self.mac and pkt['Ether'].type == 2048)

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
