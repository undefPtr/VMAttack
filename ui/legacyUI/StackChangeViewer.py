# coding=utf-8
"""旧版（legacy）UI：栈变化分析查看器。

与 ui 下同名实现职责相同：列出执行过程中栈地址、映射到的 CPU 寄存器及取值变化，
便于对照虚拟寄存器表示（vr）理解栈行为。
"""
__author__ = 'Anatoli Kalysch'

from ui.PluginViewer import PluginViewer
from ui.UIManager import QtGui


####################
### STACK CHANGE ###
####################
class StackChangeViewer(PluginViewer):
    def __init__(self, vr, sorted, stack_changes, title='Stack Changes Analysis (legacy)'):
        # context should be a dictionary containing the backward traced result of each relevant register
        super(StackChangeViewer, self).__init__(title)
        self.vr = vr
        self.sorted = sorted
        self.stack_changes = stack_changes


    def PopulateModel(self):
        for key in self.sorted:
            sa = QtGui.QStandardItem('%s' % key)
            chg = QtGui.QStandardItem('%s' % self.stack_changes[key])

            if key in self.vr.values():
                reg = QtGui.QStandardItem('%s' % [k for k in self.vr.keys() if self.vr[k] == key][0])
            else:
                reg = QtGui.QStandardItem(' ')
            self.sim.appendRow([sa, reg, chg])


        self.treeView.resizeColumnToContents(0)
        self.treeView.resizeColumnToContents(1)
        self.treeView.resizeColumnToContents(2)


    def PopulateForm(self):
        ### init widgets
        # model
        self.sim = QtGui.QStandardItemModel()
        self.sim.setHorizontalHeaderLabels(['Stack Address', 'Address Mapped to CPU Reg', 'Value Changes during Execution'])

        # tree view
        self.treeView = QtGui.QTreeView()
        self.treeView.setExpandsOnDoubleClick(True)
        self.treeView.setSortingEnabled(False)
        self.treeView.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)

        ### populate widgets
        # fill model with data
        self.PopulateModel()

        self.treeView.setModel(self.sim)
        # finalize layout
        layout = QtGui.QGridLayout()
        layout.addWidget(self.treeView)

        self.parent.setLayout(layout)


    def isVisible(self):
        try:
            return self.treeView.isVisible()
        except:
            return False
