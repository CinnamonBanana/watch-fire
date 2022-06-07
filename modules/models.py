from PyQt5.QtCore import QAbstractTableModel, Qt
from PyQt5.QtGui import QColor
from datetime import datetime

class TableModel(QAbstractTableModel):
    
    colors = {
        'Y':'#FCFC99',
        'G':'#79DE79',
        'R':'#FB6962'
    }

    def __init__(self, header, data):
        super(TableModel, self).__init__()
        self.data = data
        self.header = header

    def data(self, index, role):
        if role == Qt.DisplayRole:
            val = self.data[index.row()][index.column()]
            if index.column() == 3:
                return datetime.utcfromtimestamp(float(val)).strftime('%H:%M:%S %Y-%m-%d')
            return val
        if role == Qt.BackgroundRole:
            if index.column() == 0:
                return QColor(self.colors[self.data[index.row()][index.column()]])
        if role == Qt.TextAlignmentRole:
            return Qt.AlignCenter

    def rowCount(self, index):
        return len(self.data)

    def columnCount(self, index):
        if len(self.data):
            return len(self.data[0])
        else:
            return 0

    def headerData(self, col, orientation, role):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.header[col]
        return None

class CSVModel(QAbstractTableModel):

    proto = [
        'Unknown',
        'TCP',
        'UDP',
        'ICMP'
        ]

    def __init__(self, header, data):
        super(CSVModel, self).__init__()
        self.data = data
        self.header = header
    
    def data(self, index, role):
        if role == Qt.DisplayRole:
            val = self.data[index.row()][index.column()]
            if index.column() == 0:
                return self.proto[int(self.data[index.row()][index.column()])]
            return val
        if role == Qt.TextAlignmentRole:
            return Qt.AlignCenter

    def rowCount(self, index):
        return len(self.data)

    def columnCount(self, index):
        if len(self.data):
            return len(self.data[0])
        else:
            return 0

    def headerData(self, col, orientation, role):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.header[col]
        return None