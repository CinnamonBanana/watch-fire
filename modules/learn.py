import time
import random
import pickle
import os

try:
    import autosklearn.classification
except:
    import sklearn
import numpy as np
from sklearn.model_selection import train_test_split
import pandas as pd
from PyQt5.QtCore import QObject, pyqtSignal


class LearnerSignals(QObject):
    progressAdd = pyqtSignal(object)
    endLearn = pyqtSignal()

class Learner(QObject):
    def __init__(self, parent=None):
        super(Learner, self).__init__(parent)
        self.signals = LearnerSignals()
        self.exiting = False
        self.i = 0
    
    def stop(self):
        print('Stopped Learner thread')
        self.exiting = True

    def run(self):
            if self.exiting: return
        # try: 
        #     ## LEARNER
        #     df = pd.read_csv('./csv/data.csv')
        #     self.signals.progressAdd.emit(5)
            
        #     rslt = df
        #     labels = np.array(rslt.pop('suspicious'))
            
        #     train, test, train_labels, test_labels = train_test_split(rslt, labels, 
        #                                                             stratify = labels,
        #                                                             test_size = 0.3)
        #     self.signals.progressAdd.emit(25)
            
        #     regr = autosklearn.regression.AutoSklearnRegressor(time_left_for_this_task=120,
        #                                                         per_run_time_limit=30,
        #                                                         include={'classifier': 'mlp'})
        #     regr.fit(train, train_labels)
        #     self.signals.progressAdd.emit(90)
            
        #     os.rename('model', 'oldmodel')
        #     pickle.dump(regr, open('model', "wb"))
        #     self.signals.progressAdd.emit(100)
            
        #     self.signals.endLearn.emit()
        
        # except:
            ## DUMMY        
            for self.i in range(101):
                self.signals.progressAdd.emit(self.i)
                tim = round(random.uniform(0, 0.1), 3)
                # print(self.i, tim)
                time.sleep(tim)
                self.i+=random.randint(1, 5)
            else:
                self.signals.endLearn.emit()
