#coding:utf-8

"""
x86/x64 寄存器家族分类工具。

将通用整数寄存器按「同一物理寄存器的不同位宽别名」划分为若干类，例如 eax、ax、al、ah
同属一类，便于在分析中统一比较或按位宽选取规范名称。
"""

_registerClasses = [
    ['al', 'ah', 'ax', 'eax', 'rax'],
    ['bl', 'bh', 'bx', 'ebx', 'rbx'],
    ['cl', 'ch', 'cx', 'ecx', 'rcx'],
    ['dl', 'dh', 'dx', 'edx', 'rdx'],
    ['bpl', 'bp', 'ebp', 'rbp'],
    ['dil', 'di', 'edi', 'rdi'],
    ['sil', 'si', 'esi', 'rsi'],
    ['spl', 'sp', 'esp', 'rsp'],
    ['r8l', 'r8w', 'r8d', 'r8'],
    ['r9l', 'r9w', 'r9d', 'r9'],
    ['r10l', 'r10w', 'r10d', 'r10'],
    ['r11l', 'r11w', 'r11d', 'r11'],
    ['r12l', 'r12w', 'r12d', 'r12'],
    ['r13l', 'r13w', 'r13d', 'r13'],
    ['r14l', 'r14w', 'r14d', 'r14'],
    ['r15l', 'r15w', 'r15d', 'r15']
    ]


def get_reg_class(reg):
    """
    查询寄存器所属家族（类）的索引。

    同一物理寄存器的不同写法（如 ax 与 eax）返回相同类编号；未在表中的名称返回 None。

    返回寄存器的类型/type，如 ax、eax 返回 0。
    @brief Determines the register class of a given reg.
    All different register names that address the same register
    belong to the same register class e.g.: 'ax' and 'eax'
    @param reg name of register
    @return register class
    """
    lreg = reg.lower()
    ret_value = None
    for pos, reg_list in enumerate(_registerClasses):
        for reg in reg_list:
            found = False
            if reg == lreg:
                found = True
                ret_value = pos
                break
        if found:
            break
    return ret_value


def get_reg_by_size(reg_class, reg_size):
    """
    按家族索引与位宽（比特）返回该家族下的规范寄存器名字符串。

    例如 reg_class=0、reg_size=32 时返回 eax；类无效或位宽无法映射时返回 None。

    通过 reg 的 class 索引以及 reg 的大小，返回具体的寄存器。
    @brief Determines the register by its size and class
    @param reg_class The register class of the register
    @param reg_size The size of the register
    @return Name of the register
    """
    if reg_class >= len(_registerClasses):
        return None
    num_regs = len(_registerClasses[reg_class])
    if num_regs < 4:
        return None
    reg_index = -1
    if reg_size > 32: # 64-bit regs
        reg_index = num_regs - 1
    elif reg_size > 16: # 32-bit regs
        reg_index = num_regs - 2
    elif reg_size > 8: # 16-bit regs
        reg_index = num_regs - 3
    elif reg_size > 0: # 8-bit regs
        reg_index = 0
    else:
        return None
    return _registerClasses[reg_class][reg_index]


def get_size_by_reg(reg):
    """
    根据寄存器名称返回其位宽（8/16/32/64）；名称不在家族列表中或无法匹配时返回 None。

    获取寄存器的 bit 位大小。
    @brief Determines the size of the given register
    @param reg Register
    @return Size of register
    """
    reg_class = get_reg_class(reg)
    num_regs = len(_registerClasses[reg_class])
    for index, test_reg in enumerate(_registerClasses[reg_class]):
        if test_reg == reg:
            break
    else: # no break
        return None
    if index == (num_regs-1):
        return 64
    elif index == (num_regs-2):
        return 32
    elif index == (num_regs-3):
        return 16
    else:
        return 8



def get_reg_class_lst(reg_class):
    """
    返回指定家族内所有别名列表（小写），例如 reg_class=0 时返回 eax 族各名称。

    返回某一个类的寄存器 list，reg_class=0 则返回 eax 族的寄存器。
    @return Returns the whole list of a given register class
    """
    return _registerClasses[reg_class]
