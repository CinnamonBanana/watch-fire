from numpy import broadcast
import scapy.all as scapy
from PyQt5.QtCore import QThread, pyqtSignal

class Sniffer(QThread):
    framesReceived = pyqtSignal(object)
    broadcastReceived = pyqtSignal(object)

    def __init__(self, adapter, parent=None):
        super(Sniffer, self).__init__(parent)
        self.adapter = adapter
        self.exiting = False
        self.mac = "b0:10:41:1b:30:79"

    def __del__(self):
        self.exiting = True
        self.wait()

    def run(self):
        scapy.sniff(iface=self.adapter, store=False, prn=self.pktProcess, lfilter=self.isNotOutgoing)
    
    def pktProcess(self, pkt):
        if pkt['Ether'].dst == 'ff:ff:ff:ff:ff:ff':
            self.broadcastReceived.emit(pkt)
        else:
            self.framesReceived.emit(pkt)

    def isNotOutgoing(self, pkt):
        return (pkt['Ether'].src != self.mac and pkt['Ether'].type == 2048)

if __name__ == "__main__":
    adapter = "Dell Wireless 1705 802.11b|g|n (2.4GHZ)"

    MYMAC = "b0:10:41:1b:30:79"
    ANDROID = "a8:9c:ed:75:77:41"

    def isNotOutgoing(pkt):
        #return pkt['Ether'].src != MYMAC and pkt['Ether'].type == 2048
        return pkt['Ether'].src == ANDROID

    def http_header(pkt):
        print(pkt.show())
        
    scapy.sniff(iface=adapter, store=False, prn=http_header, lfilter=isNotOutgoing)
