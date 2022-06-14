import socket
import psutil
import time

from PyQt5.QtCore import QObject, QTimer, pyqtSignal

def get_ifs():
    ifs = psutil.net_if_addrs()
    data = {i: ifs[i][-1].address.lower().replace('-', ':') for i in ifs.keys()}
    data['\\Device\\NPF_{7EA7E4D1-E26B-460B-A942-7A380B1E50BB}'] = 'b0:10:41:1b:30:79'
    return data

def get_token(data, ip, port=6060):
    received = False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # Connect to server and send data
            sock.settimeout(10)
            sock.connect((ip, port))
            sock.sendall(bytes(str(data) + "\n", "utf-8"))

            # Receive data from the server and shut down
            received = str(sock.recv(1024), "utf-8")
    except:
        received = False
    return received

class SenderSignals(QObject):
    run = pyqtSignal()

class Sender(QObject):
    def __init__(self):
        super(Sender, self).__init__()
        self.signals = SenderSignals()
        self.signals.run.connect(self.run)
        self.exiting = False
        self.queue = []
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except:
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Enable broadcasting mode
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.server.settimeout(0.5)

    def stop(self):
        print('Stopped Sender thread')
        self.exiting = True

    def bcast(self, data):
        self.message = bytes(str(data)+"\n", 'utf-8')  
        for i in range(5):
            self.server.sendto(self.message, ('<broadcast>', 37020))
            

    def add_msg(self, data):
        self.queue.append(data)
        self.signals.run.emit()

    def run(self):
        if self.exiting: return
        if self.queue:
            self.bcast(self.queue.pop(0))
