# coding=utf-8
"""Immunity Debugger 调试器适配：继承 Debugger，面向 ImmunityDbg 环境。

提供断点、单步、轨迹生成与局部执行等接口的统一封装；当前实现为占位桩，
各方法返回 TODO 提示，后续可接入 Immunity 脚本 API 完成实际调试与采迹逻辑。
"""
__author__ = 'Anatoli Kalysch'


from Debugger import Debugger
import sys

# TODO this is a stub and will be completed later
class OllyDebugger(Debugger):
    def __init__(self, *args):
        super(Debugger, self).__init__()
        self.steps = 0
        self.hooked = False
        self.bp = None
        self.callstack = {}
        self.prev_bp_ea = None
        self._module_name = 'ImmunityDbg'
        self.start_time = 0
        self.end_time = 0

        self.error_msg = "TODO!"

    def set_breakpoint(self, address):
        return self.error_msg

    def remove_breakpoint(self, address):
        return self.error_msg

    def single_step(self):
        return self.error_msg

    def gen_trace(self):
        return self.error_msg

    def part_exec(self, start=None, end=None, reg_ctx=None):
        return self.error_msg

    def get_env_context(self):
        return self.error_msg