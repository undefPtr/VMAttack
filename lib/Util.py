# coding=utf-8
"""
IDA 插件/脚本用通用工具集合。

包含：根据 IDA 信息判断架构、导入/库函数与系统库段识别、反汇编项着色、
CPU 上下文键布局占位，以及与寄存器规范化、十六进制清洗、简单算术表达式相关的辅助函数。
"""

__author__ = 'Anatoli Kalysch'

import idaapi

from idc import *
from idautils import *
from lib.Register import get_reg_class, get_reg_by_size

### ARCHITECTURE AND REGISTER FUNCTIONALITY ###
# IDA PRO execution context layouts 64
ctx_layout_64 = {'st':['ST0', 'ST1', 'ST2', 'ST3', 'ST4', 'ST5', 'ST6', 'ST7'],
              'ctrl':'CTRL',
              'segments':['CS', 'DS', 'ES', 'FS', 'GS', 'SS'],
              'registers':['RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RBP', 'RSP', 'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15'],
              'flags':'EFL',
              'multimedia':['XMM0', 'XMM1', 'XMM2', 'XMM3', 'XMM4', 'XMM5', 'XMM6', 'XMM7', 'XMM8', 'XMM9', 'XMM10', 'XMM11', 'XMM12', 'XMM13', 'XMM14', 'XMM15', 'MXCSR', 'MM0', 'MM1', 'MM2', 'MM3', 'MM4', 'MM5', 'MM6', 'MM7']}

# IDA PRO execution context layouts 86
ctx_layout_86 = {'st':['ST0', 'ST1', 'ST2', 'ST3', 'ST4', 'ST5', 'ST6', 'ST7'],
                 'ctrl':'CTRL',
                 'segments':['CS', 'DS', 'ES', 'FS', 'GS', 'SS'],
                 'registers':['EAX', 'EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'EBP', 'ESP'],
                 'flags':'EFL',
                 'multimedia':['MXCSR', 'MM0', 'MM1', 'MM2', 'MM3', 'MM4', 'MM5', 'MM6', 'MM7']}

def get_arch_dynamic():
    """
    动态判断当前 IDA/调试环境下的目标架构位宽。

    Determine the execution environments architecture.
    :return: 64 或 32 表示 x64/x86；无法判定时返回 None
    """
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        return 64
    elif info.is_32bit():
        return 32
    else:
        env = idaapi.dbg_get_registers()
        if env[17][0] == 'RAX':
            return 64
        elif env[17][0] == 'EAX':
            return 32
        else:
            return None


###############################
# LIB DETECTION FUNCTIONALITY #
###############################
def is_import_or_lib_func(ea):
    """
    Is ea part of an imported function or a known library?
    @param ea: any ea within the function scope
    @return: True if function is either imported or a known library function.
    """

    return Functions(ea).flags & (idaapi.FUNC_LIB | idaapi.FUNC_THUNK)

def is_system_lib(ea):
    """
    Returns true if a segment belongs to a system library, in which case we don't want to recursively hook calls.
    Covers Windows, Linux, Mac, Android, iOS
    @param ea: an effective address within a function
    """
    name = idc.SegName(ea)

    if not name:
        return False

    # the below is for Windows kernel debugging
    if name == 'nt':
        return True

    sysfolders = [re.compile("\\\\windows\\\\", re.I), re.compile("\\\\Program Files ", re.I), re.compile("/usr/", re.I), \
                  re.compile("/system/", re.I), re.compile("/lib/", re.I)]

    m = idc.GetFirstModule()
    while m:
        path = idc.GetModuleName(m)
        if re.search(name, path):
            if any(regex.search(path) for regex in sysfolders):
                return True
            else:
                return False
        m = idc.GetNextModule(m)

    return False

############################
### COLORS FUNCTIONALITY ###
############################
# current palette are mainly shades of red, green, blue
palette = [0xccccff, 0xb3b3ff, 0x9999ff, 0x8080ff, 0x6666ff, 0x4d4dff, 0x3333ff, 0x1a1aff, 0x0000ff, 0x00ff00, 0xff0000]


def remove_all_colors():
    heads = Heads(BeginEA(), BADADDR)
    for head in heads:
        SetColor(head, CIC_ITEM, 0xFFFFFF)

def set_new_color(addr):
    # get current color of addr_line and set the next escalation color
    current_color = GetColor(addr, CIC_ITEM)
    SetColor(addr, CIC_ITEM, set_new_color(current_color))
    current_color = 0xFFFFFF
    # processing
    if current_color == 0xFFFFFF:
        return palette[0]
    if current_color in palette:
        pos = palette.index(current_color)
        if pos == len(palette) - 1:
            return palette[pos]
        else:
            return palette[pos + 1]

    return 0xFFFFFF


class CPU(object):
    """
    占位用的 CPU 执行上下文结构：寄存器、FPU 栈、段寄存器集合、标志与多媒体寄存器初值字典。

    与上方 ctx_layout_* 描述的分组概念对应，供跟踪或模拟时作为键空间参考。
    """
    def __init__(self):
        """初始化各寄存器分组容器与默认初值。"""
        self.registers = {}
        self.st = {'ST0':0, 'ST1':0, 'ST2':0, 'ST3':0, 'ST4':0, 'ST5':0, 'ST6':0, 'ST7':0}
        self.ctrl = {'CTRL':0}
        self.segments = {'CS', 'DS', 'ES', 'FS', 'GS', 'SS'}
        self.registers = {'RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RBP', 'RSP', 'R8', 'R9', 'R10', 'R11', 'R12', 'R13',
                     'R14', 'R15'}
        self.flags = {}
        self.multimedia = {'XMM0':0, 'XMM1':0, 'XMM2':0, 'XMM3':0, 'XMM4':0, 'XMM5':0, 'XMM6':0, 'XMM7':0, 'XMM8':0, 'XMM9':0, 'XMM10':0, 'XMM11':0,
                      'XMM12':0, 'XMM13':0, 'XMM14':0, 'XMM15':0, 'MXCSR':0, 'MM0':0, 'MM1':0, 'MM2':0, 'MM3':0, 'MM4':0, 'MM5':0, 'MM6':0, 'MM7':0}


def get_reg(reg_string, reg_size):
    """
    将任意别名与目标位宽映射为 Traceline.ctx 等结构中使用的规范寄存器名字符串（小写族内名）。

    returns the register name to be used as key with a Traceline.ctx object
    :param reg_string: any string representing a reg, e.g. rax, RAX, eax, ah, al, etc.
    :param reg_size: size in bit of the registers in Traceline.ctx, e.g. 64, 32, 16
    :return: reg_string of the ctx keys, e.g. rax
    """
    return get_reg_by_size(get_reg_class(reg_string), reg_size)

def sanitize_hex(hex_string):
    """
    从输入串中仅保留十六进制数字并转为大写，去掉 0x、后缀 h 等非数字字符。

    Sanitize input to uppercase hex string
    :param hex_string: the input hex string, e.g. 0xabc, 0xABC, abc, 28h
    :return: sanitized hex string, e.g. ABC or 28
    """
    return ''.join(c for c in hex_string.upper() if c in '0123456789ABCDEF')

def interprete_math_expr(operands, expr):
    """
    对操作数列表从左到右做归约：expr 为 +、- 或 *；未知运算符抛出异常。

    :param operands: list of operands
    :param expr: the expression to use: + or - or *
    :return: mathematical result
    """
    result = operands[0]
    for operand in operands[1:]:
        if expr == '+':
            result += operand
        elif expr == '-':
            result -= operand
        elif expr == '*':
            result *= operand
        else:
            raise Exception('[*] Exception parsing math expression: Unknown Value \'%s\'!' % expr)
    return result

