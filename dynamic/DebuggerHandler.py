# coding=utf-8
"""
调试器与 Trace 的集中管理模块。

本模块提供 ``DebuggerHandler`` 单例，用于在 IDA 环境下统一完成调试器加载与切换、
指令级 Trace 的生成，以及 Trace 与磁盘之间的导入导出。``load`` / ``save`` 负责
多种外部 Trace 格式的解析与 VMAttack JSON 序列化；``get_dh`` 为全局获取该单例的入口。
"""
from dynamic.TraceRepresentation import Trace, Traceline
from lib.Logging import get_log

__author__ = 'Anatoli Kalysch'


import json

from collections import defaultdict
from copy import deepcopy
from lib.Util import remove_all_colors
from ui.UIManager import QtGui
from IDADebugger import IDADebugger

from idautils import *
from idaapi import *
from idc import *


class DebuggerHandler(object):
    """
    调试器处理类（建议通过 ``get_dh`` 以单例方式使用）。

    统一管理具体调试器实例的创建与切换、Hook 生命周期，以及当前 ``Trace`` 的持有与
    指令级 Trace 的生成。构造时可传入自定义加载函数以替换默认的 ``IDADebugger``；
    若 IDA 当前未选择调试器，会回退加载 Win32 调试器。
    """
    def __init__(self, func=None):
        """
        初始化调试器后端。

        :param func: 可选。若提供，则绑定为实例方法 ``load_dbg`` 并调用以创建调试器；
            若为 ``None``，则使用默认的 ``IDADebugger``。当 IDA 未设置调试器名称时，
            会记录日志并加载 ``Win32`` 调试器。
        """
        self.dbg = None
        # if function for loading the Debugger is given execute it
        if func is not None:
            self.load_dbg = types.MethodType(func, self)
            self.dbg = self.load_dbg()
        else:
            self.dbg = IDADebugger()

        if dbg_get_name() is None:
            get_log().log('[DBG] Debugger name was none so loaded default Windows32 debugger\n')
            LoadDebugger('Win32', 0)


    @property
    def check(self):
        """当前是否已持有有效的调试器实例（``self.dbg`` 非 ``None``）。"""
        return self.dbg is not None

    @property
    def hooked(self):
        """底层调试器是否处于 Hook/附加状态（委托 ``self.dbg.hooked``）。"""
        return self.dbg.hooked

    @property
    def trace(self):
        """
        当前持有的指令 Trace（``Trace`` 实例）。

        赋值时会校验类型必须为 ``Trace``。
        """
        return self._trace
    
    @trace.setter
    def trace(self, value):
        """将当前指令 Trace 设为 ``value``（运行期断言为 ``Trace`` 实例）。"""
        assert isinstance(value, Trace)
        self._trace = value

    def switch_debugger(self, func):
        """
        切换调试器实现。

        将 ``func`` 绑定为 ``load_dbg``，重新实例化 ``self.dbg`` 并立即对其调用 ``hook_dbg``。
        ``func`` 为 ``None`` 时记录日志并抛出异常。

        :param func: 用于创建新调试器实例的可调用对象（将被绑定为实例方法）。
        """
        if func is None:
            get_log().log('[DBG] Instantiation function was empty so no debugger chosen\n')
            raise Exception('[*] empty function! Cannot instantiate Debugger!')

        self.load_dbg = types.MethodType(func, self)
        self.dbg = self.load_dbg()
        self.dbg.hook_dbg()

    def gen_instruction_trace(self, start=BeginEA(), end=BADADDR):
        """
        在 ``start``、``end`` 参数所确定的地址区间内生成指令级 Trace（具体语义由底层 ``gen_trace`` 决定）。

        会初始化 ``self._trace``，必要时通过 ``load_dbg`` 补全调试器；清除 IDA 图形颜色后
        Hook 调试器、调用 ``gen_trace``，结束时 ``unhook_dbg`` 并返回生成的 ``Trace``
        （与 ``self._trace`` 为同一对象）。

        :param start: 起始地址，默认当前光标/入口 ``BeginEA()``。
        :param end: 结束地址，默认 ``BADADDR``。
        :return: 填充后的 ``Trace`` 对象。
        """
        self._trace = Trace()
        if not self.check:
            self.dbg = self.load_dbg()
        self.dbg.hook_dbg()
        remove_all_colors()
        trace = self.dbg.gen_trace(start, end)
        self.dbg.unhook_dbg()
        return trace


def ida_offset(string):
    """
    Converts non-IDA conforming offset representation to a more IDAesk form.
    :param string: a non IDA conform string
    :return: IDA conform string
    """
    segment, rest = string.split(':', 2)
    offset_start = rest.rfind('+')
    offset = rest[offset_start + 1:-1]
    operands = rest[1:offset_start]

    # ds:off_40439c[eax * 4]
    return '%s:off_%s[%s]' % (segment, offset, operands)


def load():
    """
    通过文件对话框（失败时回退到当前目录首个 ``*.txt`` 或 ``asktext``）选择文件并加载 Trace。

    仅处理扩展名为 ``.txt`` 或 ``.json`` 的路径；否则返回 ``None``。用户取消选择时亦返回 ``None``。
    成功解析后，根据最后一条记录的寄存器上下文设置 ``trace.ctx_reg_size``（64/32），并提示加载完成。

    **格式识别与解析逻辑（按分支顺序）：**

    1. **VMAttack JSON**（``path`` 以 ``.json`` 结尾，或 ``json.load`` 得到 ``dict``）\
       视为键为 ``\"0\"``, ``\"1\"``, … 的字典；每条记录为六元组列表：\
       ``[thread_id, addr, disasm, ctx, comment, grade]``，依次构造 ``Traceline`` 并写入 ``grade``。

    2. **IDA Win32Dbg 文本 Trace**（首行以 ``\"Thread \"`` 开头）\
       从第 4 行起按行读取，遇下一行以 ``Thread`` 开头则停止。每行按制表符分列：\
       第 0 列为十六进制线程 ID；第 1 列为 ``段:地址`` 或 ``段:符号±偏移`` / ``loc_`` 等形式，\
       结合当前 IDB 中各段的 ``Functions`` 映射解析为 ``ea``；第 2 列为反汇编文本，经拆分、\
       操作数与 ``[ebp+0]`` 等规范化后得到 ``disasm`` 列表；第 3 列为空格分隔的 ``reg=value`` 上下文，\
       合并进跨行的 ``context`` 字典。每条有效行追加一条 ``Traceline``。

    3. **Immunity Debugger**（首行以 ``\"Address\\t\"`` 开头）\
       从第 2 行起解析，遇含 ``Run trace closed`` 或 ``Process terminated`` 的行结束。\
       制表符分列：第 0 列为指令地址（十六进制）；第 1 列为线程名，以字符序值和作为数值型 ``thread_id``；\
       第 2 列为反汇编，去掉 ``dword ptr`` 前缀，必要时用 ``ida_offset`` 把复杂寻址改成 IDA 风格；\
       第 4 列（索引 ``3``）为逗号分隔的寄存器上下文。无效行在含 ``terminated`` / ``entry point`` 时忽略。

    4. **OllyDbg**（第二行以 ``\"main\\t\"`` 开头，用于与 Immunity 表头区分）\
       从第 2 行起至含 ``Logging stopped`` 的行为止。列含义与 Immunity 类似但列序不同：\
       第 0 列为线程名（同样转换为数值 ``thread_id``），第 1 列为地址，第 2 列为反汇编，\
       其余列解析寄存器上下文；复杂内存操作数同样可经 ``ida_offset`` 规范化。

    :return: 解析得到的 ``Trace``；未选择文件、扩展名不支持或解析失败时返回 ``None`` 或抛出异常。
    """
    path = ''
    try:
        fd = QtGui.QFileDialog()
        fd.setFileMode(QtGui.QFileDialog.AnyFile)
        fd.setFilters(["Text files (*.txt)", "JSON files (*.json)"])
        fd.setWindowTitle('Load Trace ...')
        if fd.exec_():
            path = fd.selectedFiles()[0]
        else:
            path = None
    except:
        msg('A Problem occured with the file selector dialog, first *.txt file in the current working directory was choosen!')
        for f in os.listdir(os.getcwd()):
            if f.endswith('txt'):
                path = f
        if path == '':
            path = asktext(40, '', 'Please provide the full path to the trace file: ')

    if path is not None:
        get_log().log('[TRC] Loaded the trace at %s\n' % path)
        if path.endswith('.txt'):
            with open(path, 'r') as f:
                lines = f.readlines()
        elif path.endswith('.json'):
            with open(path) as f:
                lines = json.load(f)
        else:
            return None
        trace = Trace()

        functions = {SegName(addr): {GetFunctionName(ea): ea for ea in Functions(SegStart(addr), SegEnd(addr))} for addr in Segments()}

        try:
            context = defaultdict(lambda: False)

            # framework json trace
            if isinstance(lines, dict) or path.endswith('.json'):
                get_log().log('[TRC] The trace seems to be a VMAttack trace\n')
                for index in range(len(lines.keys())):
                    line = lines[str(index)]
                    t = Traceline(thread_id=line[0], addr=line[1], disasm=line[2], ctx=line[3], comment=line[4])
                    t.grade = line[5]
                    trace.append(t)

            # ida trace via Win32Dbg
            elif lines[0].startswith('Thread '):
                for i in lines[3:]:
                    if i.startswith('Thread'):
                        break
                    values = i.split('\t')
                    # thread id
                    thread_id = int(values[0], 16)

                    # addr
                    addr = BADADDR
                    func_name = values[1].strip(' ').split(':')
                    if len(func_name) == 2:
                        try:  # .segment:addr
                            addr = int(func_name[1], 16)
                        except:
                            try:  # .segment:func_name+offset
                                offset = int(func_name[1].split('+')[1], 16)
                                name = func_name[1].split('+')[0]
                                addr = functions[func_name[0]][name] + offset
                            except:
                                try:  # .segment:func_name-offset
                                    offset = int(i.split('-')[1].split(' ')[0], 16)
                                    name = func_name[1].split('-')[0]
                                    addr = functions[func_name[0]][name] - offset
                                except:
                                    if not func_name[1].startswith('loc_'):  # .segment:func_name
                                        addr = functions[func_name[0]][func_name[1]]
                                    else:  # .segment:jmp_location
                                        addr = int(func_name[1][4:], 16)
                    elif len(func_name) == 3:
                        addr = int(func_name[2][4:], 16)

                    # disasm
                    disasm = values[2].strip(' ').lower()
                    disasm = disasm.split('  ')
                    disasm = [x.lstrip() for x in disasm]
                    disasm = filter(None, disasm)
                    if len(disasm) > 1 and disasm[1].__contains__(', '):
                        temp = disasm.pop(1)
                        for elem in temp.split(', '):
                            disasm.append(elem.lstrip().lstrip('0').rstrip('h'))

                    # remove [ebp+0]
                    for dis in disasm:
                        if dis.__contains__('[ebp+0]'):
                            dis.replace('[ebp+0]', '[ebp]')

                    # context
                    ida_ctx = values[3].strip(' ').split(' ')
                    for value in ida_ctx:
                        try:
                            a, b = value.split('=')
                            if len(b) > 1:
                                b = ''.join(c.rstrip('\r\n') for c in b.lstrip('0'))
                            if b == '':
                                b = '0'
                            context[a.lower()] = b
                        except:
                            pass

                    trace.append(Traceline(thread_id=thread_id, addr=addr, disasm=disasm, ctx=deepcopy(context)))
            # immunity trace
            elif lines[0].startswith('Address	'):
                for i in lines[1:]:
                    if i.__contains__('Run trace closed') or i.__contains__('Process terminated'):
                        break
                    values = i.split('\t')
                    try:
                        # thread_id
                        thread_id = sum(ord(c) for c in values[1]) # immunity uses names, e.g. main
                        # addr
                        try:
                            addr = int(values[0], 16)
                        except:
                            addr = BADADDR
                        # disasm
                        disasm = values[2].lower().rstrip('\r\n')
                        disasm = disasm.split(' ', 1)
                        if len(disasm) > 1 and disasm[1].__contains__(','):
                            temp = disasm.pop(1)
                            for elem in temp.split(','):
                                disasm.append(elem.lstrip('0'))
                        disasm = [x.split('dword ptr ')[1] if x.__contains__('dword ptr ') else x for x in disasm]
                        if len(disasm) == 2 and len(re.findall(r'.*\[.*[\+\-\*].*[\+\-\*].*\].*', disasm[1])) > 0:
                            disasm[1] = ida_offset(disasm[1])
                        # context
                        if len(values) > 3:
                            olly_ctx = values[3].lstrip(' ').rstrip('\r\n').split(',')
                            for value in olly_ctx:
                                try:
                                    a, b = value.split('=')
                                    if len(b) > 1:
                                        b = ''.join(c for c in b.lstrip('0') if c not in '\n\r\t')
                                    if b == '':
                                        b = '0'
                                    context[a.lower()] = b
                                except:
                                    pass
                        trace.append(Traceline(thread_id=thread_id, addr=addr, disasm=disasm, ctx=deepcopy(context)))
                    except:
                        if i.__contains__('terminated') or i.__contains__('entry point'):
                            pass

            # olly trace
            elif lines[1].startswith('main	'):
                for i in lines[1:]:
                    if i.__contains__('Logging stopped'):
                        break
                    values = i.split('\t')
                    # thread_id
                    thread_id = sum(ord(c) for c in values[0])  # olly uses names, e.g. main
                    # addr
                    try:
                        addr = int(values[1], 16)
                    except:
                        addr = BADADDR
                    # disasm
                    disasm = values[2].lower().rstrip('\r\n')
                    disasm = disasm.split(' ', 1)
                    if len(disasm) > 1 and disasm[1].__contains__(','):
                        temp = disasm.pop(1)
                        for elem in temp.split(','):
                            disasm.append(elem.lstrip('0'))

                    disasm = [x.split('dword ptr ')[1] if x.__contains__('dword ptr ') else x for x in disasm]
                    if len(disasm) == 2 and len(re.findall(r'.*\[.*[\+\-\*].*[\+\-\*].*\].*', disasm[1])) > 0:
                        disasm[1] = ida_offset(disasm[1])
                    # context
                    if len(values) > 3:
                        olly_ctx = values[3].lstrip(' ').rstrip('\r\n').split(',')
                        for value in olly_ctx:
                            try:
                                a, b = value.split('=')
                                if len(b) > 1:
                                    b = ''.join(c for c in b.lstrip('0') if c not in '\n\r\t')
                                if b == '':
                                    b = '0'
                                context[a.lower()] = b
                            except:
                                pass
                    trace.append(Traceline(thread_id=thread_id, addr=addr, disasm=disasm, ctx=deepcopy(context)))


            if 'rax' in trace[-1].ctx.keys():
                trace.ctx_reg_size = 64
            elif 'eax' in trace[-1].ctx.keys() and 'rax' not in trace[-1].ctx.keys():
                trace.ctx_reg_size = 32
            msg("[*] Trace Loaded!\n")
            return trace
        except Exception, e:
            raise Exception('[*] Exception occured: \n%s\n' % (e.message))
    else:
        return None


def save(trace):
    """
    将当前 ``Trace`` 序列化为 VMAttack JSON 并写入磁盘。

    通过文件对话框选择保存路径（过滤器为 JSON）；若对话框异常则回退到\
    ``当前工作目录 + get_root_filename() + '_trace_<时间戳>.json'``。\
    写入前若路径已带 ``.json`` 后缀会先去掉再统一追加 ``.json``。\
    序列化对象为 ``{ 索引 i: ['%x' % thread_id, '%x' % addr, disasm, ctx, comment, grade] }``，\
    与 ``load`` 所识别的 JSON 格式一致。``trace`` 为空时抛出异常。

    :param trace: 待保存的 ``Trace`` 实例（可索引、含上述字段）。
    """
    try:
        fd = QtGui.QFileDialog()
        fd.setFileMode(QtGui.QFileDialog.AnyFile)
        fd.setFilter('JSON Files (*.json)')
        fd.setWindowTitle('Save Trace ...')
        if fd.exec_():
            path = fd.selectedFiles()[0]
        else:
            path = None
    except:
        path = os.getcwd() + get_root_filename() + '_trace_%s.json' % time.time()

    if path is not None:
        if path.endswith('.json'):
            path = path[:-5]
        with open(path + '.json', 'w') as f:
            if trace:
                obj = {i:['%x' % trace[i].thread_id,
                          '%x' % trace[i].addr,
                          trace[i].disasm,
                          trace[i].ctx,
                          trace[i].comment,
                          trace[i].grade] for i in range(len(trace))}
                f.write(json.dumps(obj))
                msg('[*] Trace saved!\n')
            else:
                raise Exception("[*] Trace seems to be None:\n %s" % trace)

# Singelton DebuggerHandler
dbg_handl = None

def get_dh(choice=None):
    """
    返回全局唯一的 ``DebuggerHandler`` 实例。

    首次调用时用 ``choice`` 构造 ``DebuggerHandler`` 并缓存；之后忽略 ``choice``，始终返回同一对象。

    :param choice: 可选，传给 ``DebuggerHandler.__init__`` 的自定义加载函数（仅首次生效）。
    :return: 单例 ``DebuggerHandler``。
    """
    global dbg_handl
    if dbg_handl is None:
        dbg_handl = DebuggerHandler(choice)
    return dbg_handl