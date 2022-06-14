from PyQt5.QtCore import QRunnable, QObject, pyqtSignal, pyqtSlot

from modules.utils import *

class BufferSignals(QObject):
    callAlert = pyqtSignal(str)
    run = pyqtSignal()
    flush = pyqtSignal(dict)


class Buffer(QObject):

    def __init__(self, parent=None, askForIP = True):
        super(Buffer, self).__init__()
        self.signals = BufferSignals()
        self.signals.run.connect(self.run)
        self.exiting = False
        self.askForIP = askForIP
        self.app = parent
        self.queue = []
        self.buffer = {}

    def stop(self):
        print('Stopped Buffer thread')
        self.exiting = True

    def add_pkt(self, pkt):
        self.queue.append(pkt)
        self.signals.run.emit()
    
    def form_data(self, pkt, show = False):
        ip = pkt.ip.src
        curtime = float(pkt.sniff_timestamp)
        if ip not in self.buffer:
            self.buffer[ip] = {}
            self.buffer[ip]['suspicious'] = 1 if self.askForIP else 0
            if self.askForIP:
                self.buffer[ip]['suspicious'] = int(self.call_Alert(ip))
        prot = pkt.transport_layer
        if prot is None:
            prot = pkt.highest_layer
        if prot not in self.buffer[ip]:
            self.new_proto(ip, prot, curtime)
        if curtime-self.buffer[ip][prot]['start']<=5:
            try:
                port = int(pkt[prot].dstport)
            except:
                port=0
            self.buffer[ip][prot]['pkt']['ports'] += port
            self.buffer[ip][prot]['pkt']['portmin'] = min(port, self.buffer[ip][prot]['pkt']['portmin'])
            self.buffer[ip][prot]['pkt']['portmax'] = max(port, self.buffer[ip][prot]['pkt']['portmax'])
            self.buffer[ip][prot]['pkt']['delay'] += curtime - self.buffer[ip][prot]['last']
            self.buffer[ip][prot]['last'] = curtime
            self.buffer[ip][prot]['pkt']['count'] += 1
            self.buffer[ip][prot]['pkt']['length'] += int(pkt.length)
            if show: print(f'==========\n{ip}\n{self.buffer[ip][prot]["pkt"]}')
            return False
        else:
            a = self.buffer[ip].pop(prot, False)['pkt']
            return {
                'ip':ip,
                'suspicious':self.buffer[ip]['suspicious'], 
                'data':get_avg(get_num_proto(prot), a)
            }

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
        self.app.responses[ip] = None
        self.signals.callAlert.emit(ip)
        while self.app.responses[ip] is None:
            time.sleep(0.1)
        return self.app.responses[ip]

    def run(self):
        if self.exiting: return
        if self.queue:
            data = self.form_data(self.queue.pop(0))
            if data:
                self.signals.flush.emit(data)

if __name__ == '__main__':
    pass