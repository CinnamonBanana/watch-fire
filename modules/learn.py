import time
import random

import sklearn
import pandas as pd
import scapy.all as scapy
from PyQt5.QtCore import QThread, pyqtSignal

class Learner(QThread):
    progressAdd = pyqtSignal(object)
    endLearn = pyqtSignal(object)

    def __init__(self, parent=None):
        super(Learner, self).__init__(parent)
        self.exiting = False
        self.i = 0
    
    def __del__(self):
        self.exiting = True
        self.wait()

    def run(self):
        for self.i in range(101):
            self.progressAdd.emit(self.i)
            tim = round(random.uniform(0, 0.1), 3)
            # print(self.i, tim)
            time.sleep(tim)
            self.i+=random.randint(1, 5)
        else:
            self.endLearn.emit(None)
