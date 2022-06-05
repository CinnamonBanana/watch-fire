import socket
import time

from PyQt5.QtCore import QThread

class Sender(QThread):
    def __init__(self, parent=None):
        super(Sender, self).__init__(parent)
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

    def __del__(self):
        self.exiting = True
        self.wait()

    def bcast(self, data):
        message = bytes(str(data)+"\n", 'utf-8')
        for i in range(5):
            self.server.sendto(message, ('<broadcast>', 37020))
            time.sleep(0.05)

    def add_msg(self, data):
        self.queue.append(data)

    def run(self):
        while not self.exiting:
            if self.queue:
                # print(f"{self.queue=}")
                self.bcast(self.queue.pop(0))
