import pyshark
from PyQt5.QtCore import QObject, pyqtSignal, pyqtSlot

from inet import *

class SnifferSignals(QObject):
    framesReceived = pyqtSignal(object)
    broadcastReceived = pyqtSignal(dict)
    serverReceived = pyqtSignal(str)
    startFailed = pyqtSignal(str)

class Sniffer(QObject):

    EXCLUDE_PROTOS = [
        'DNS',
        'MDNS',
        'ARP',
        'SSDP'
    ]

    def __init__(self, adapter, mmac=''):
        super(Sniffer, self).__init__()
        self.adapter = adapter
        self.exiting = False
        self.mymac = mmac
        self.serverIp = serverip
        self.signals = SnifferSignals()
        self.capture = pyshark.LiveCapture(interface=self.adapter)

    def stop(self):
        print('Stopped Sniffer thread')
        self.exiting = True

    def run(self):
        if self.exiting: return
        try:
            for pkt in self.capture.sniff_continuously():
                if self.exiting: break
                if self.filter(pkt):
                    self.pktProcess(pkt)
        except Exception as e:
            print(f'Error {e}')
            self.stop()
            self.signals.startFailed.emit(f"Error: {e}")

    def pktProcess(self, pkt):
        ip = pkt.ip.src
        prot = pkt.transport_layer
        if pkt.ip.dst in ['255.255.255.255']:
            load = self.decodeMsg(pkt)
            if load:
                self.signals.broadcastReceived.emit({'src':ip, 'msg': load})
        else:
            if ip == self.serverIp and prot in ['UDP','TCP']:
                if load:
                    self.signals.serverReceived.emit({'src':ip, 'msg': load})
            else:
                self.signals.framesReceived.emit(pkt)

    def decodeMsg(self, pkt):
        try:
            load = bytearray.fromhex(pkt.data.data).decode()
            return load if load else False
        except:
            pass
        

    def filter(self, pkt):
        if hasattr(pkt, 'ip') and all(k not in pkt for k in self.EXCLUDE_PROTOS):
            return pkt.eth.src != self.mymac

if __name__ == "__main__":
    adapter = '\\Device\\NPF_{7EA7E4D1-E26B-460B-A942-7A380B1E50BB}'
    sniff = Sniffer(adapter)
    sniff.run()

    # ANDROID = "a8:9c:ed:75:77:41"
