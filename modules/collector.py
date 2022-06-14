import csv

from PyQt5.QtCore import QObject, pyqtSignal, pyqtSlot


class CollectorSignals(QObject):
    updateCSV = pyqtSignal()
    run = pyqtSignal()

class Collector(QObject):

    def __init__(self):
        super(Collector, self).__init__()
        self.signals = CollectorSignals()
        self.signals.run.connect(self.run)
        self.exiting = False
        self.queue = []
        self.filename = './csv/data.csv'
        self.fieldnames = ['proto','ports', 'portmin', 'portmax', 'delay', 'count', 'length', 'suspicious']
        try:
            with open(self.filename, 'r', buffering=1) as csvfile:
                pass
        except:
            with open(self.filename, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames)
                writer.writeheader()

    def stop(self):
        print('Stopped Collector thread')
        self.exiting = True

    def add_data(self, data):
        self.queue.append(data)
        self.signals.run.emit()
    
    def collect(self, data, show = False):
        data['data']['suspicious'] = data['suspicious']
        if show: print(f"========\n{data['ip']}\n{data=}")
        if not data['suspicious']:
            with open(self.filename, 'a', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames)
                writer.writerow(data['data'])
            self.signals.updateCSV.emit()

    def run(self):
        if self.exiting: return
        if self.queue:
            self.collect(self.queue.pop(0))

if __name__ == '__main__':
    pass