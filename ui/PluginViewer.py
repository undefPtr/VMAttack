# coding=utf-8
"""插件查看器基类。

继承 IDA PluginForm，在 OnCreate 中通过 UIManager.form_to_widget 取得父控件并调用
子类实现的 PopulateForm。各分析结果的表格/树形窗体均从此类派生，统一 Show 与关闭行为。
"""
__author__ = 'Anatoli Kalysch'

from idaapi import PluginForm, msg
from ui.UIManager import form_to_widget


class PluginViewer(PluginForm):
    def __init__(self, title):
        super(PluginViewer, self).__init__()
        self.title = title

    def Show(self, **kwargs):
        return PluginForm.Show(self, self.title, options=PluginForm.FORM_PERSIST)

    def OnCreate(self, form):
        # Get parent widget
        self.parent = form_to_widget(form)
        self.PopulateForm()

    def PopulateForm(self):
        ### do stuff
        pass

    def OnClose(self, form):
        msg("Closed %s.\n" % self.title)