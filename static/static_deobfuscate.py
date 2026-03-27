# -*- coding: utf-8 -*-
"""
静态反混淆模块 - 将虚拟机字节码静态还原为可读的伪指令

核心处理流程：
1. 逐字节读取VM字节码
2. 通过跳转表(jump table)将每个字节码映射到对应的x86 handler代码
3. 分析handler的x86指令序列，识别为虚拟指令(VmInstruction)
4. 转换为伪指令(PseudoInstruction)的push/pop表示
5. 应用多轮优化（变量替换、赋值消减、NOR→NOT转换等）
6. 划分基本块，构建抽象VM控制流图

关键概念：
- 跳转表：VM用字节码值 × 指针大小 + 基址，索引handler地址
- Catch指令：handler中通过ESI/RSI从字节码流读取附加参数的指令
- VM上下文(VMContext)：code_start、code_end、base_addr、vm_addr 4个关键地址

@author: Tobias Krauss, Anatoli Kalysch
"""
from idaapi import *
from idautils import *
from idc import *
from lib.Instruction import Instruction
from lib.Optimize import *
from lib.Register import (get_reg_by_size,
                          get_reg_class)
from lib.VmInstruction import VmInstruction
from lib.VmInstruction import (add_ret_pop,
                               to_vpush)

import distorm3
import lib.PseudoInstruction as PI
import lib.StartVal as SV
from ui.BBGraphViewer import show_graph
from lib.VMRepresentation import VMContext, get_vmr

# 基本块着色方案（6种颜色循环使用）
bb_colors = [0xddddff, 0xffdddd, 0xddffdd, 0xffddff, 0xffffdd, 0xddffff]


def calc_code_addr(instr, base):
    """
    通过跳转表将VM字节码映射到对应的x86 handler地址

    跳转表结构: base[bytecode] = handler_addr
      32位: 每项4字节, handler_addr = Dword(bytecode * 4 + base)
      64位: 每项8字节, handler_addr = Qword(bytecode * 8 + base)

    @param instr: VM字节码值(0x00-0xFF)
    @param base: 跳转表基址
    @return handler的x86代码起始地址
    """
    if SV.dissassm_type == SV.ASSEMBLER_32:
        return Dword((instr * 4) + base)
    else:
        return Qword((instr * 8) + base)


def get_instruction_list(vc, base):
    """
    反汇编一个字节码对应的整个x86 handler，返回Instruction列表

    执行流:
    1. calc_code_addr() 查跳转表 → 获取handler起始地址
    2. 若该地址未被IDA识别为代码 → 强制MakeCode
    3. 从handler起始逐条反汇编:
       - 读取指令字节 → 创建 Instruction(addr, bytes)
       - 无条件跳转(jmp dispatch) → 丢弃该指令，终止（回到VM dispatch循环）
       - ret → 保留该指令，终止（VM函数返回）
       - 其他 → 保留，继续下一条

    @param vc VM字节码值(0x00-0xFF)
    @param base 跳转表基址
    @return List[Instruction] — 该handler的全部有效x86指令
    """
    inst_addr = calc_code_addr(vc, base)
    # 确保handler地址处被IDA识别为代码（可能被误标为数据）
    if not isCode(GetFlags(inst_addr)):
        MakeUnknown(inst_addr, 1, DOUNK_SIMPLE)
        MakeCode(inst_addr)
    inst_lst = []
    end_of_instruction_block = False
    while not end_of_instruction_block:
        size = ItemSize(inst_addr)
        inst_bytes = GetManyBytes(inst_addr, size)
        inst = Instruction(inst_addr, inst_bytes)
        if inst.is_uncnd_jmp():
            # 无条件跳转 = 回到dispatch循环，handler结束，丢弃jmp本身
            end_of_instruction_block = True
        elif inst.is_ret():
            # ret = VM函数返回，handler结束，保留ret指令
            inst_lst.append(inst)
            end_of_instruction_block = True
        else:
            inst_lst.append(inst)
            inst_addr = NextHead(inst_addr)
    return inst_lst


def clear_comments(ea, endaddr):
    """
    @brief Can be started from ida-python-shell.
    Clears all comments form ea to endaddr
    @param ea: Startaddress to remove comments
    @param endaddr: Endaddress
    """
    while ea <= endaddr:
        MakeComm(ea, "")
        ea = ea + 1


def get_start_push(vm_addr):
    """
    提取VM函数入口处的push序列（保存调用者上下文/传递参数）

    VM函数开头的典型模式:
      push ebx          ← 保存寄存器
      push edi          ← 保存寄存器
      push 0x12345678   ← 传递参数(字节码起始地址等)
      push eax          ← 保存寄存器
      ...
      mov ebp, esp      ← 建立VM栈帧（终止标志）

    从vm_addr逐条反汇编，直到遇到 "mov ebp, esp"(is_mov_basep_stackp)
    终止条件之前的所有指令 → 转为vpush伪指令，表示函数参数

    @param vm_addr VM函数起始地址
    @return List[Instruction] — 入口处的push序列
    """
    inst_addr = vm_addr
    ret = []
    end_of_instruction_block = False
    while not end_of_instruction_block:
        size = ItemSize(inst_addr)
        inst_bytes = GetManyBytes(inst_addr, size)
        inst = Instruction(inst_addr, inst_bytes)
        if inst.is_mov_basep_stackp():
            # "mov ebp, esp" 标志着VM栈帧建立完成，入口push序列结束
            end_of_instruction_block = True
        else:
            inst_addr = NextHead(inst_addr)
            ret.append(inst)
    return ret


jump_dict = {}


def get_catch_reg(reg, length):
    """
    根据catch指令的mov大小确定正确的寄存器名

    catch指令从字节码流中读取附加参数到某个寄存器，但mov可能使用
    子寄存器(al/ax/eax)。需要根据实际读取的字节数确定正确的寄存器名。

    例: catch读取1字节 → 寄存器应为 al (8位)
        catch读取4字节 → 寄存器应为 eax (32位)

    @param reg handler代码中catch指令使用的寄存器名
    @param length catch读取的字节数(1/2/4/8)
    @return 正确大小的寄存器名，或空字符串（无法确定时）
    """
    reg_class = get_reg_class(reg)
    if reg_class == None:
        return ''
    catch_reg = get_reg_by_size(reg_class, length * 8)
    if catch_reg == None:
        catch_reg = ''
    return catch_reg


def first_deobfuscate(ea, base, endaddr):
    """
    主反混淆函数 - 将ea到endaddr之间的虚拟字节码转换为VmInstruction列表

    工作流程（对每个字节码）：
    1. 读取当前地址的字节值作为字节码
    2. 通过calc_code_addr()查跳转表获取handler地址
    3. 调用get_instruction_list()反汇编handler的x86指令序列
    4. 检测是否有catch指令（从字节码流读取1/2/4/8字节参数）
    5. 构造VmInstruction对象（自动识别为vpush/vpop/vadd等虚拟指令）
    6. 遇到vjmp/vret时处理控制流（可能需要用户交互确认跳转目标）

    @param ea 虚拟字节码起始地址
    @param base 跳转表基址
    @param endaddr 虚拟字节码结束地址
    @return VmInstruction列表
    """
    curraddr = ea
    instr_lst = []
    vminst_lst = []
    catch_value = None

    # ─── 主循环：逐字节遍历VM字节码 ─────────────────────────────
    while curraddr <= endaddr:
        inst_addr = curraddr

        # ① 读取当前地址的字节值作为VM操作码
        vc = Byte(curraddr)

        # ② 查跳转表 → 反汇编handler → 得到x86指令列表
        instr_lst = get_instruction_list(vc, base)
        if len(instr_lst) < 1:
            print 'error occured'
            curraddr += 1
            continue

        # ③ 检测handler中是否有catch指令
        #    catch指令通过ESI/RSI从字节码流中读取附加参数
        #    例: movzx ecx, byte ptr [esi+1] → 从字节码流读1字节到ecx
        has_catch = False
        catch_instr = None
        for pos, inst in enumerate(instr_lst):
            if inst.is_catch_instr():
                catch_instr = inst
                has_catch = True
                break

        # ④ 根据catch指令的mov大小，从字节码流中提取附加参数值
        #    字节码格式: [opcode][catch_param...]
        #    无catch → 单字节操作码, length=1
        #    有catch → opcode + 1/2/4/8字节参数
        if has_catch:
            if catch_instr.is_byte_mov():
                catch_value = Byte(curraddr + 1)     # 读取1字节参数
                length = 2                            # 操作码(1) + 参数(1)
            elif catch_instr.is_word_mov():
                catch_value = Word(curraddr + 1)     # 读取2字节参数
                length = 3                            # 操作码(1) + 参数(2)
            elif catch_instr.is_double_mov():
                catch_value = Dword(curraddr + 1)    # 读取4字节参数
                length = 5                            # 操作码(1) + 参数(4)
            elif catch_instr.is_quad_mov():
                catch_value = Qword(curraddr + 1)    # 读取8字节参数
                length = 9                            # 操作码(1) + 参数(8)
        else:
            length = 1  # 无附加参数，单字节操作码

        curraddr += length  # 前进到下一条VM字节码
        MakeUnknown(inst_addr, length, DOUNK_SIMPLE)  # 在IDA中标记为数据

        # 确定catch寄存器的正确大小名称
        if has_catch:
            catch_reg = get_catch_reg(catch_instr.get_op_str(1), length - 1)
        else:
            catch_reg = ''

        # ⑤ 构造VmInstruction — 自动进行15种虚拟指令模式匹配
        #    内部流程: 分离Vinstructions/Instructions → get_pseudo_code()
        #    → 匹配成功设置Pseudocode → replace_catch_reg()用值替换寄存器
        vm_inst = VmInstruction(instr_lst, catch_value,
                                catch_reg, inst_addr)
        vminst_lst.append(vm_inst)
        if (vm_inst.Pseudocode == None):
            continue

        # ⑥ 控制流处理 — 遇到vjmp/vret时检查是否需要用户介入
        #    若下一地址有正常x86代码(非VM字节码)，弹出对话框:
        #    - 用户选Yes: 继续反混淆该地址
        #    - 用户选No: 手动输入新的继续地址
        #    jump_dict缓存用户选择，避免重复询问
        if (vm_inst.Pseudocode.inst_type == PI.JMP_T or
                    vm_inst.Pseudocode.inst_type == PI.RET_T):
            if isCode(GetFlags(curraddr)):
                if curraddr in jump_dict:
                    curraddr = jump_dict[curraddr]
                    continue
                Jump(curraddr)
                answer = AskYN(0,
                               ('Should this regular x86 at address ' +
                                '{0:#x} instructions be deobfuscated?'.format(curraddr)))
                if answer == 0 or answer == -1:
                    old_addr = curraddr
                    curraddr = AskAddr(curraddr,
                                       'Insert Address where deobfuscation will be continued!')
                    jump_dict[old_addr] = curraddr
    return vminst_lst


def deobfuscate_all(base):
    """
    @brief Converts every possible virtual code to VmInstructions
    @param base Address of the jumptable of the virtual machine.
    @return List of all possible VmInstructions
    @remark This function is not used for deobfuscate the virtual code,
    its just a test if every possible virtual instruction is translated
    properly.
    """
    catch_byte = 0x00
    vm_inst_lst = []
    while catch_byte <= 0xff:
        inst_lst = get_instruction_list(catch_byte, base)
        vm_inst = VmInstruction(inst_lst, 0x0, '',
                                (SV.dissassm_type / 8 * catch_byte) + base)
        vm_inst.get_pseudo_code()
        vm_inst_lst.append(vm_inst)
        catch_byte += 1
    return vm_inst_lst


def display_ps_inst(ps_inst_lst):
    """
    @brief Displays PseudoInstructions in the comments of Ida
    @param ps_inst_lst List of PseudoInstructions
    """
    length = len(ps_inst_lst)
    comm = ''
    for pos, item in enumerate(ps_inst_lst):
        if pos < length - 1:
            addr = item.addr
            next_addr = ps_inst_lst[pos + 1].addr
        else:
            addr = item.addr
            next_addr = item.addr + 1
        if addr == next_addr:
            comm += str(item)[:len(str(item)) - 1] + '\t\t' + item.comment + '\n'
        else:
            comm += str(item)[:len(str(item)) - 1] + '\t\t' + item.comment + '\n'
            MakeComm(addr, comm)
            comm = ''


def display_vm_inst(vm_inst_lst):
    """
    @brief Displays VirtualInstructions in the comments of Ida
    @param vm_inst_lst List of VirtualInstructions
    """
    length = len(vm_inst_lst)
    comm = ''
    for pos, item in enumerate(vm_inst_lst):
        if pos < length - 1:
            addr = item.addr
            next_addr = vm_inst_lst[pos + 1].addr
        else:
            addr = item.addr
            next_addr = item.addr + 1
        if addr == next_addr:
            comm += str(item)[:len(str(item)) - 1] + '\n'
        else:
            comm += str(item)[:len(str(item)) - 1] + '\n'
            MakeComm(addr, comm)
            comm = ''


def read_in_comments(start, end):
    """
    @brief Read in all ida comments between start and end
    @param start Address where to start reading
    @param end Address where to end reading
    @return List of Tuples (comment, address of comment)
    """
    ret = []
    addr = start
    while addr <= end:
        comment = CommentEx(addr, 0)
        r_comment = CommentEx(addr, 1)
        if comment == None and r_comment == None:
            addr += 1
        elif r_comment == None and comment != None:
            ret.append((comment, addr))
            addr += 1
        elif r_comment != None and comment == None:
            print 'r_comment'
            ret.append((r_comment, addr))
            addr += 1
        else:
            erg_comm = r_comment + '\n' + comment
            ret.append((erg_comm, addr))
            addr += 1
    return ret


def find_start(start, end):
    """
    @brief tries to find startaddress of function due to
    crossrefernces
    
    @param start Startaddress of searching
    @param end Endaddress
    @return Startaddress of obfuscated function
    """
    addr = start
    erg = 0
    counter = 0
    while addr <= end:
        a = DfirstB(addr)
        if (a != BADADDR):
            counter += 1
            erg = addr
        addr += 1
    if counter != 1:
        print 'could not resolve start_addr'
        return BADADDR
    else:
        return erg


# Badaddr is set from Ida, so i can use this
def set_dissassembly_type():
    """
    @brief Determines if disassembly is 32 or 64 bitdeobfuscate
    """
    if BADADDR == 0xffffffffffffffff:
        SV.dissassm_type = SV.ASSEMBLER_64
    else:
        SV.dissassm_type = SV.ASSEMBLER_32


def get_jaddr_from_comments(pp_lst, comment_lst):
    """
    @brief reads in jump addresses wich were set by the
    reverse engineer
    
    @param pp_lst List of PseudoInstructions in push/pop represtentation
    @param comment_lst List of comments
    @return List of tuples (set jump address, address of jump instruction)
    """
    ret = []
    for comment, caddr in comment_lst:
        if 'jumps to: ' in comment:
            index = comment.find('jumps to: 0x')
            if index == -1:
                continue
            jmps = comment[index:len(comment)]
            index = jmps.find('0x')
            if index == -1:
                continue
            jmps = jmps[index:len(jmps)]
            str_lst = jmps.split(', ')
            for sub_str in str_lst:
                ret.append((long(sub_str, 16), caddr))
        else:
            continue
    return ret


def get_jmp_input_found(cjmp_addrs, jmp_addrs):
    """
    @brief Cobines the automatic found jump addresses
    with those from the reverse engineer
    
    @remark those addresses which were entered have preference
    @param cjmp_addrs Addresses form the reverse engineer
    @param jmp_addrs Automatic found addresses
    @return List of tuples (jump address, address of jump instruction)
    """
    ejmp_addrs = []
    ejmp_addrs += cjmp_addrs
    for (jaddr, inst_addr) in jmp_addrs:
        found = False
        for _, cinst_addr in cjmp_addrs:
            if cinst_addr == inst_addr:
                found = True
        if not found:
            ejmp_addrs.append((jaddr, inst_addr))
    return ejmp_addrs


def change_comments(pp_lst, cjmp_addrs):
    """
    @brief Sets the entered jump addresses in the comments
    of the PseudoInstructions
    
    @param pp_lst  List of PseudoInstructions in push/pop represtentation
    @param cjmp_addrs List of tuples (set jump address,
    address of jump instruction)
    """
    for item in pp_lst:
        if item.inst_type == PI.JMP_T:
            found_vals = []
            for jaddr, inst_addr in cjmp_addrs:
                if inst_addr == item.addr:
                    found_vals.append(jaddr)
            if len(found_vals) == 0:
                continue
            comment = 'jumps to: '
            found_addr = False
            for addr in found_vals:
                comment += '{0:#x}, '.format(addr)
            comment = comment[:len(comment) - 2]
            item.comment = comment


def get_jmp_addr(bb):
    """
    @param bb List of PseudoInstructions of one basic block
    @return Address of jump instruction in this basic block
    """
    for inst in bb:
        if inst.inst_type == PI.JMP_T:
            return inst.addr
    return None


def has_ret(bb):
    """
    @param bb List of PseudoInstructions of one basic block
    @return True if ret instruction is part of basic block, False otherwise
    """
    return (lambda bb: True if 'ret_T' in map(lambda inst: inst.inst_type, bb) else False)(bb)

def get_jmp_loc(jmp_addr, jmp_addrs):
    """
    @param jmp_addr Address of jmp instruction
    @param jmp_addrs List of Tuples (jump address, address of jmp instruction)
    @return A list of all addresses a jmp instruction can jump to
    """
    return [jmp_to for jmp_to, j_addr in jmp_addrs if j_addr == jmp_addr]


def deobfuscate(code_saddr,  base_addr, code_eaddr, vm_addr, display=4, real_start=0):
    """
    核心反混淆编排函数 - 完成从字节码到优化伪指令+CFG的全部流程

    流程：
    1. 确定反汇编类型(32/64位)
    2. 读取已有IDA注释(用于保留逆向工程师手动标注的跳转地址)
    3. 提取VM函数入口的push序列(函数参数)
    4. first_deobfuscate(): 字节码→VmInstruction
    5. add_ret_pop(): 处理vret的pop序列
    6. make_pop_push_rep(): VmInstruction→push/pop伪指令表示
    7. get_jmp_addresses(): 递归搜索跳转目标地址
    8. find_basic_blocks(): 划分基本块
    9. optimize(): 对每个基本块执行优化管线
    10. 在IDA中显示注释/抽象VM控制流图

    @param code_saddr 混淆代码起始地址
    @param base_addr 跳转表基址
    @param code_eaddr 混淆代码结束地址
    @param vm_addr VM函数起始地址
    @param display 输出模式: 0=VmInstruction, 1=push/pop表示, 2+=完全优化+CFG
    @param real_start 函数真实入口地址
    @return 找到的最小跳转地址
    """
    # ═══════════════════════════════════════════════════════════════
    # Step 1: 环境初始化 — 根据IDA的BADADDR判断32/64位模式
    #   设置 SV.dissassm_type，影响后续 distorm3 解码模式和跳转表项宽度
    # ═══════════════════════════════════════════════════════════════
    set_dissassembly_type()

    # ═══════════════════════════════════════════════════════════════
    # Step 2: 读取已有IDA注释 — 保留逆向工程师之前手动标注的跳转地址
    #   格式示例: "jumps to: 0x4012AB, 0x4012CD"
    #   这些注释会在 Step 7 中与自动发现的跳转地址合并
    # ═══════════════════════════════════════════════════════════════
    comment_list = read_in_comments(code_saddr, code_eaddr)

    # ═══════════════════════════════════════════════════════════════
    # Step 3: 确定混淆函数的真实入口地址
    #   优先使用调用者指定的 real_start；
    #   否则通过交叉引用(xref)启发式搜索：找到恰好被引用1次的地址
    #   兜底回退到 code_saddr（字节码起始地址）
    # ═══════════════════════════════════════════════════════════════
    if real_start == 0:
        start_addr = find_start(code_saddr, code_eaddr)
    else:
        start_addr = real_start
    if start_addr == BADADDR:
        start_addr = code_saddr

    # ═══════════════════════════════════════════════════════════════
    # Step 4: 提取VM函数入口的push序列 → 转为vpush伪指令
    #   VM函数开头通常是一系列 push reg/imm 保存调用者上下文，
    #   直到 "mov ebp, esp" 建立VM栈帧。这些push对应函数参数。
    #   get_start_push(): 逐条创建Instruction → List[Instruction]
    #   to_vpush(): Instruction → vpush PseudoInstruction
    #   产出的 f_start_lst 会在 Step 6 插入到 start_addr 对应位置
    # ═══════════════════════════════════════════════════════════════
    f_start_lst = []
    if vm_addr != 0:
        f_start_lst = get_start_push(vm_addr)
        f_start_lst = to_vpush(f_start_lst, start_addr)

    # ═══════════════════════════════════════════════════════════════
    # Step 5: 核心反混淆 — 字节码 → VmInstruction 列表
    #   first_deobfuscate() 逐字节遍历 [code_saddr, code_eaddr]:
    #     每个字节码 → 查跳转表得handler地址 → 反汇编handler为Instruction列表
    #     → 检测catch指令(读取1/2/4/8字节附加参数)
    #     → 构造VmInstruction(自动匹配15种虚拟指令模式)
    #     → 遇到vjmp/vret时可能弹出用户交互对话框
    #   deobfuscate_all() 是测试函数，遍历所有256种字节码进行翻译
    # ═══════════════════════════════════════════════════════════════
    vm_inst_lst = first_deobfuscate(code_saddr, base_addr, code_eaddr)
    vm_inst_lst1 = deobfuscate_all(base_addr)
    display_vm_inst(vm_inst_lst1)

    # ═══════════════════════════════════════════════════════════════
    # Step 6: VmInstruction → push/pop 伪指令表示
    #   add_ret_pop(): 将vret handler中的pop序列转为vpop伪指令
    #     （vret前有一系列pop恢复寄存器的操作，需要显式表示）
    #   make_pop_push_rep(): 将每条高级虚拟指令展开为push/pop序列
    #     例: vadd(op1, op2) → vpop T1; vpop T2; vpush(T1+T2); vpush flags
    #     引入临时变量T_xx使数据流显式化
    #   在start_addr处插入Step 4产生的函数参数vpush序列
    # ═══════════════════════════════════════════════════════════════
    pseudo_lst = add_ret_pop(vm_inst_lst)
    push_pop_lst = []
    lst = []
    for inst in pseudo_lst:
        if inst.addr == start_addr:
            lst = f_start_lst  # 在函数入口处插入参数push序列
        lst += inst.make_pop_push_rep()
        for rep in lst:
            push_pop_lst.append(rep)
        lst = []

    # ═══════════════════════════════════════════════════════════════
    # Step 7: 跳转地址解析 — 合并自动发现与手动标注
    #   get_jaddr_from_comments(): 从IDA注释中提取手动标注的跳转目标
    #   get_jmp_addresses(): 递归回溯数据流自动发现跳转目标
    #     对每个vjmp指令，追踪其操作数来源（最大递归深度20层）
    #     支持多目标跳转（跳转前有连续push立即数 → 跳转表）
    #   get_jmp_input_found(): 合并两个来源，手动标注优先
    #   change_comments(): 将跳转目标写回IDA注释供下次使用
    # ═══════════════════════════════════════════════════════════════
    cjmp_addrs = get_jaddr_from_comments(push_pop_lst, comment_list)
    jmp_addrs = get_jmp_addresses(push_pop_lst, code_eaddr)
    jmp_addrs = get_jmp_input_found(cjmp_addrs, jmp_addrs)
    change_comments(push_pop_lst, cjmp_addrs)

    # ═══════════════════════════════════════════════════════════════
    # Step 8: 基本块划分 + IDA着色
    #   find_basic_blocks(): 经典leader算法
    #     leader来源: start_addr, vjmp/vret后的下一条, 所有跳转目标
    #     排序去重后相邻leader构成(start, end)区间 → 基本块边界
    #   color_basic_blocks(): 用6种颜色在IDA中循环着色各基本块
    #   make_bb_lists(): 按基本块边界切分push_pop_lst
    #   has_locals(): 检测函数是否有局部变量(影响优化策略)
    # ═══════════════════════════════════════════════════════════════
    basic_blocks = find_basic_blocks(push_pop_lst, start_addr, jmp_addrs)
    if basic_blocks == None:
        basic_blocks = [(code_saddr, code_eaddr)]
    color_basic_blocks(basic_blocks)
    basic_lst = make_bb_lists(push_pop_lst, basic_blocks)
    has_loc = has_locals(basic_lst)
    clear_comments(code_saddr, code_eaddr)

    # ═══════════════════════════════════════════════════════════════
    # Step 9-10: 优化 + 输出展示
    #   display=0: 显示原始VmInstruction（最底层，无优化）
    #   display=1: 显示push/pop伪指令（中间表示，无优化）
    #   display>=2: 对每个基本块执行10步优化管线 → 显示优化后伪指令
    #     并构建抽象VM控制流图(CFG):
    #     - 节点: 每个非空基本块 → "bb0", "bb1", ...
    #     - 边的构建逻辑:
    #       · 有ret的基本块 → 无出边（函数返回）
    #       · 无jmp的基本块 → 顺序连接到下一基本块(fall-through)
    #       · 有jmp的基本块 → 查找所有跳转目标，连接到目标所在基本块
    #     - 调用BBGraphViewer.show_graph()在IDA中渲染图形
    # ═══════════════════════════════════════════════════════════════
    if display == 0:
        vm_list = f_start_lst + pseudo_lst
        display_vm_inst(vm_list)
    elif display == 1:
        display_ps_inst(push_pop_lst)
    else:
        opt_basic = []
        display_lst = []
        nodes = []
        edges = []
        for lst in basic_lst:
            opt_lst = optimize(lst, has_loc)
            display_lst += opt_lst
            opt_basic.append(opt_lst)
        display_ps_inst(display_lst)
        for node, bb in enumerate(opt_basic):
            if bb == []:
                continue
            nodes.append(('bb%d' % (node)))

            if has_ret(bb):
                continue

            jmp_addr = get_jmp_addr(bb)
            if jmp_addr == None:
                edges.append(('bb%d' % (node), 'bb%d' % (node + 1)))
            else:
                jmp_locs = get_jmp_loc(jmp_addr, jmp_addrs)
                for loc in jmp_locs:
                    for pos, (saddr, eaddr) in enumerate(basic_blocks):
                        if loc >= saddr and loc < eaddr:
                            edges.append(('bb%d' % (node), 'bb%d' % (pos)))
        try:
            g = show_graph(nodes, edges, opt_basic, jmp_addrs, basic_blocks, real_start)
        except Exception, e:
            print e.message

    # 返回所有跳转目标中的最小地址，供外层start()迭代使用
    # 若存在比当前code_saddr更小的跳转目标，start()会从该地址重新执行deobfuscate
    if jmp_addrs != []:
        min_jmp = min(jmp_addrs)[0]
    else:
        min_jmp = BADADDR
    return min_jmp


def start(code_saddr, base_addr, code_eaddr, vm_addr, display=4, real_start=0):
    """
    迭代驱动入口 — 反复调用deobfuscate直到覆盖所有前向跳转

    问题背景: VM字节码中可能存在前向跳转(跳转到比当前起始地址更小的地址)。
    第一轮deobfuscate可能只处理了部分字节码，但发现跳转目标在更前面。

    迭代机制:
      deobfuscate() 返回所有跳转目标中的最小地址 min_jmp
      若 min_jmp < 当前起始地址 → 从 min_jmp 重新开始
      循环终止: min_jmp >= 当前起始地址（所有字节码已覆盖）

    @param code_saddr 混淆代码起始地址
    @param base_addr 跳转表基址
    @param code_eaddr 混淆代码结束地址
    @param vm_addr VM函数起始地址
    @param display 输出模式: 0=VmInstruction, 1=push/pop, 2+=优化+CFG
    @param real_start 函数真实入口地址
    """
    old_min = BADADDR
    n_min = code_saddr
    start = real_start
    while old_min > n_min:
        old_min = n_min
        n_min = deobfuscate(old_min, base_addr, code_eaddr, vm_addr, display, start)
        if start == 0:
            start = code_saddr

def color_basic_blocks(basic_lst):
    """
    @brief Colors the basic blocks
    @param basic_lst List of Tuples: (address start basic block,
    address end basic block)
    """
    color = 0
    for start, end in basic_lst:
        if (start + 1 == end):
            continue
        pos = start
        while pos < end:
            SetColor(pos, CIC_ITEM, bb_colors[color % len(bb_colors)])
            pos += 1
        color += 1


def make_bb_lists(pp_lst, basic_lst):
    """
    @brief Generates basic blocks and returns them in a list
    @param pp_lst  List of PseudoInstructions in push/pop represtentation
    @param basic_lst List of Tuples: (address start basic block,
    address end basic block)
    @return List of basic block lists
    """
    bb_lists = []
    for (s_addr, e_addr) in basic_lst:
        bb_lst = []
        for inst in pp_lst:
            if inst.addr >= s_addr and inst.addr < e_addr:
                bb_lst.append(inst)
        bb_lists.append(bb_lst)
    return bb_lists


def has_locals(bb_lsts):
    """
    @brief Determines if the function reserves space for local variables
    @param List of basic blocks
    @return True if function has locals, False otherwise
    """
    has_ebp_mov = False
    for bb in bb_lsts:
        has_ebp_mov = False
        for inst in bb:
            if inst.inst_type == PI.MOV_EBP_T:
                has_ebp_mov = True
            if inst.inst_type == PI.RET_T and has_ebp_mov:
                return True
    return False


def print_bb(bb_lsts):
    """
    @brief Print start and end of basic block; is used for debugging
    @param bb_lsts List of basic block lists
    """
    block_count = 1
    for lst in bb_lsts:
        print 'Start BB', block_count
        for inst in lst:
            print str(inst)[:len(str(inst)) - 1]
        print 'End BB', block_count
        block_count += 1


def get_distorm_info(inst_addr):
    """
    @brief Prints whole distrom3 info of the given instruction
    @param inst_addr Address of instruction
    """
    size = ItemSize(inst_addr)
    inst_bytes = GetManyBytes(inst_addr, size)
    inst = distorm3.Decompose(inst_addr,
                              inst_bytes, distorm3.Decode64Bits, 0)
    print inst[0]
    i = inst[0]
    print 'InstBytes ', i.instructionBytes
    print 'Opcode ', i.opcode
    for o in i.operands:
        print 'operand ', o
        print 'operand type', o.type
    for f in i.flags:
        print 'flag ', f
        print 'raw_flags ', i.rawFlags
    print 'inst_class ', i.instructionClass
    print 'flow_control ', i.flowControl
    print 'address ', i.address
    print 'size ', i.size
    print 'dt ', i.dt
    print 'valid ', i.valid
    print 'segment ', i.segment
    print 'unused_Prefixes ', i.unusedPrefixesMask
    print 'mnemonic ', i.mnemonic
    print 'inst_class ', i.instructionClass


def jmp_to_orig(address, base):
    """
    @brief Jumps to the executed x86 code
    @param address Address of virtual code
    @param base Address of the jumptable of the virtual machine
    """
    if SV.dissassm_type == 64:
        Jump(Qword((Byte(address) * 8) + base))
    else:
        Jump(Dword((Byte(address) * 4) + base))

        ###########
        # outdated
        ###########

        # change bad prog style
        # def reg_to_value(instr_lst, reg, value):
        #    erg = []
        #    for item in instr_lst:
        #        if reg in item.Op1:
        #            item.Op1 = item.Op1.replace(reg, '{0:#x}'.format(value))
        #        if reg in item.Op2:
        #            item.Op2 = item.Op2.replace(reg, '{0:#x}'.format(value))
        #        erg.append(item)
        #    return erg

        # def remove_vm_inst(instr_lst):
        #    erg = []
        #    for item in instr_lst:
        #        if not item.is_vinst():
        #            erg.append(item)
        #    return erg

        # seems to work
        # def test_scretch_operand():
        #    t60 = PI.ScretchOperand(PI.SVARIABLE_T, 60, 4)
        #    t10 = PI.ScretchOperand(PI.SVARIABLE_T, 60, 4)
        #    t11 = PI.ScretchOperand(PI.SVARIABLE_T, 11, 4)
        #
        #    inst0 = PI.PseudoInstruction('vpop', 0, [t60], 4)
        #    inst1 = PI.PseudoInstruction('vpop', 0, [t10], 4)
        # inst1.op_lst[0].value = 0xcaffee
        # inst0.op_lst[0].value = 0xbabe5
        #    print inst1.op_lst[0].value
        #    print '{0:#x}'.format(inst1.op_lst[0].value)


def static_vmctx(manual=False):
    """
    Compute the VM context values statically.
    :param manual: Bool -> Print result to the console
    """
    vm_ctx = VMContext()
    vm_seg_start = None
    vm_seg_end = None
    prev = 0
    # try to find the vm Segment via name -> easiest case but also easy to foil
    for addr in Segments():
        if SegName(addr).startswith('.vmp'):
            vm_seg_start = SegStart(addr)
            vm_seg_end = SegEnd(addr)
            break
    for f in Functions(vm_seg_start, vm_seg_end):
        if (GetFunctionAttr(f, FUNCATTR_END) - GetFunctionAttr(f, FUNCATTR_START)) > prev:
            prev = GetFunctionAttr(f, FUNCATTR_END) - GetFunctionAttr(f, FUNCATTR_START)
            vm_addr = f

    base_addr = NextHead(vm_addr)
    while base_addr < vm_seg_end:
        if GetMnem(base_addr).startswith('jmp'):
            try:
                base_addr = int(re.findall(r'.*off_([0123456789abcdefABCDEF]*)\[.*\]', GetOpnd(base_addr, 0))[0], 16)
                break
            except Exception, e:
                print e.message
                print e.args
        else:
            base_addr = NextHead(base_addr)
    if base_addr > vm_seg_end:
        base_addr = AskAddr(base_addr, 'Could not determine the Startaddr of the jmp table, please specify: ')

    code_start = PrevAddr(vm_seg_end)
    while not GetDisasm(code_start).__contains__('jmp'):
        code_start = PrevAddr(code_start)
    code_end = vm_seg_end
    code_start += 1

    vm_ctx.code_start = code_start
    vm_ctx.code_end = code_end
    vm_ctx.base_addr = base_addr
    vm_ctx.vm_addr = vm_addr

    vmr = get_vmr()
    vmr.vm_ctx = vm_ctx

    if manual:
        print 'Code Start: %x; Code End: %x; Base Addr: %x; VM Addr: %x' % (code_start, code_end, base_addr, vm_addr)

def static_deobfuscate(display=0, userchoice=False):
    """
    静态反混淆的用户入口 — 从IDA菜单调用

    执行流:
    1. 从VMRepresentation单例获取VM上下文(4个关键地址)
    2. 若尚未设置(BADADDR) → 自动调用static_vmctx()发现
    3. userchoice=True时弹出4个对话框让用户手动输入/修改地址
    4. 调用deobfuscate()执行完整的反混淆流程

    @param display 输出模式: 0=VmInstruction, 2=优化+CFG
    @param userchoice 是否让用户手动输入VM上下文地址
    """
    vmr = get_vmr()
    # 若VM上下文尚未初始化，先自动发现
    if vmr.code_start == BADADDR:
        try:
            vm_ctx = static_vmctx()
            vmr.vm_ctx = vm_ctx
        except Exception, e:
            print e.message
            print e.args
    if userchoice:
        # 弹出对话框让用户确认/修改4个关键地址
        code_start = AskAddr(vmr.code_start, 'Choose start of byte code:')
        code_end = AskAddr(vmr.code_end, 'Choose end of byte code:')
        base_addr = AskAddr(vmr.base_addr, 'Coose start of jmp table:')
        vm_addr = AskAddr(vmr.vm_addr, 'Choose start of the virtual machine function:')
        deobfuscate(code_start, base_addr, code_end, vm_addr, display)
    else:
        deobfuscate(vmr.code_start, vmr.base_addr, vmr.code_end, vmr.vm_addr, display)



