from PyQt5.QtCore import QAbstractTableModel, Qt
from PyQt5.QtGui import QColor
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
            return self.data[index.row()][index.column()]
        if role == Qt.BackgroundRole:
            if index.column() == 0:
                return QColor(self.colors[self.data[index.row()][index.column()]])
        if role == Qt.TextAlignmentRole:
            return Qt.AlignCenter

    def rowCount(self, index):
        return len(self.data)

    def columnCount(self, index):
        return len(self.data[0])

    def headerData(self, col, orientation, role):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.header[col]
        return None