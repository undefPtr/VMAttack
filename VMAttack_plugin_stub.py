# coding=utf-8
"""
VMAttack 的 IDA 插件加载入口桩。

IDA 从 plugins 目录载入本脚本后，读取环境变量 VMAttack 指向的主插件目录，
用 imp 动态加载同目录下的 VMAttack.py，并导出其 PLUGIN_ENTRY 供 IDA 调用。
"""
__author__ = 'Anatoli Kalysch'

import imp
import sys
import os

DEBUG = True

F_DIR = os.environ["VMAttack"]
F_NAME = "VMAttack.py"
sys.path.append(F_DIR)

plugin_path = os.path.join(F_DIR, F_NAME)
if DEBUG:
    print "Debug in VMAttack_plugin_stub.py"
    print "[VMAttack_plugin_stub.py] plugin_path:" + plugin_path
    print "[VMAttack_plugin_stub.py] __name__:" + __name__
plugin = imp.load_source(__name__, plugin_path)
PLUGIN_ENTRY = plugin.PLUGIN_ENTRY