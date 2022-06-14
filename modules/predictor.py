import pickle

import sklearn
import pandas as pd
from PyQt5.QtCore import QObject, pyqtSignal, pyqtSlot


class PredictorSignals(QObject):
    suspPredicted = pyqtSignal(dict)
    run = pyqtSignal()

class Predictor(QObject):
    def __init__(self):
        super(Predictor, self).__init__()
        self.signals = PredictorSignals()
        self.signals.run.connect(self.run)
        self.exiting = False
        self.queue = []
        self.fieldnames = ['proto','ports', 'portmin', 'portmax', 'delay', 'count', 'length']
        self.model = pickle.load(open('model', "rb"))
        self.badmodel = pickle.load(open('badmodel', "rb"))

    def stop(self):
        print('Stopped Predictor thread')
        self.exiting = True

    def add_data(self, data):
        self.queue.append(data)
        self.signals.run.emit()
    
    def predict(self, data, show = False):
        ip = data['ip']
        data = data['data']
        df = pd.DataFrame(columns=self.fieldnames)
        df.loc[0] = list(data.values())
        self.signals.suspPredicted.emit({
            'ip': ip,
            'good':self.model.predict(df)[0],
            'bad': self.badmodel.predict(df)[0]})

    def run(self):
        if self.exiting: return
        if self.queue:
            self.predict(self.queue.pop(0))

if __name__ == '__main__':
    pass