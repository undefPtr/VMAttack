# coding=utf-8
"""长时间分析任务的进度条通知小窗。

基于 Qt QWidget 与 QProgressBar，在批量填充模型时由调用方调用 pbar_set/pbar_update
反馈百分比，减轻界面“卡死”感。从 UIManager 引入 QtWidgets 以保持与主 UI 栈一致。
"""
__author__ = 'Anatoli Kalysch'

from UIManager import QtWidgets

class NotifyProgress(QtWidgets.QWidget):
    def __init__(self, name='current', *args, **kwargs):
        super(NotifyProgress, self).__init__(*args, **kwargs)
        self.analysis = name
        self.pbar = QtWidgets.QProgressBar(self)
        self.pbar.setGeometry(30, 40, 370, 25)
        self.value = 0
        self.setFixedSize(400, 100)
        self.setWindowTitle('Running %s Analysis...' % self.analysis)

    def pbar_update(self, value):
        self.value += value
        if self.value > 100:
            self.value = 100
            self.close()
        self.pbar.setValue(self.value)

    def pbar_set(self, value):
        self.pbar.setValue(value)

