# -*- coding: utf-8 -*-
"""
虚拟机指令识别模块

VmInstruction类接收一组x86 handler指令，通过模式匹配识别出对应的虚拟指令类型。
支持的虚拟指令（15种）：
  vpush  - 压栈：sub ebp + mov [ebp], value
  vpop   - 出栈：mov value, [ebp] + add ebp
  vadd   - 加法：两个操作数的add指令
  vnor   - NOR运算：not + not + and 组合
  vjmp   - 跳转：读取新的指令指针(ESI)
  vret   - 返回：ret指令
  vread  - 内存读：从内存地址读取值
  vwrite - 内存写：向内存地址写入值
  vshr   - 右移：shr指令
  vshl   - 左移：shl指令
  vshrd  - 双精度右移：shrd指令
  vshld  - 双精度左移：shld指令
  vcall  - 函数调用：call指令
  vimul  - 有符号乘法：imul指令
  vidiv  - 有符号除法：idiv指令
  vebp_mov - ebp赋值：mov ebp, ebp形式

识别策略：在handler的x86指令中寻找"特征动作"，如sub ebp表示vpush，add ebp表示vpop

@author: Tobias Krauss
"""

from lib.Instruction import Instruction
import lib.PseudoInstruction as PI
import lib.StartVal as SV
from lib.PseudoInstruction import (PseudoInstruction,
                               PseudoOperand)
from lib.Register import (get_reg_class,
                      get_size_by_reg,
                      get_reg_by_size)


def add_ret_pop(inst_lst):
    """
    将含 vret 的 VmInstruction 列表中、与返回配套的 pop 序列展开为 vpop / vpopf 伪指令。

    1. 遍历 inst_lst，若 Pseudocode 类型为 RET_T，则在其 all_instructions 中查找 pop。
    2. 多操作数 pop 转为 PseudoInstruction('vpop', ...)；单操作数 pop 转为 vpopf（flags）。
    3. 将原 vret 伪指令保留在序列末尾；非 RET 项原样保留 Pseudocode。

    @param inst_lst VmInstruction 列表
    @return 替换后的 PseudoInstruction 列表
    """
    #find ret
    ret = []
    for vinst in inst_lst:
        if vinst.Pseudocode.inst_type == PI.RET_T:
            for inst in vinst.all_instructions:
                if inst.is_pop() and len(inst) != 1:
                    p_inst = PseudoInstruction('vpop', vinst.addr,
                                               [make_op(inst, 1, -1)])
                    ret.append(p_inst)
                elif inst.is_pop() and len(inst) == 1:
                    new_op = PseudoOperand(PI.REGISTER_T,
                                           'flags',
                                           SV.dissassm_type,
                                           'flags')
                    p_inst = PseudoInstruction('vpopf', vinst.addr,
                                               [new_op])
                    ret.append(p_inst)
            ret.append(vinst.Pseudocode)
        else:
            ret.append(vinst.Pseudocode)
    return ret


def to_vpush(p_lst, start_addr):
    """
    将虚拟机函数入口处的 x86 push 序列转换为 vpush / vpushf 伪指令列表。

    1. 扫描 p_lst：非 push 的 mov 记入 wrote_values（目的寄存器 → 源操作数字符串），用于追踪立即数/别名。
    2. 对 push：按操作数类型生成 MEMORY / REGISTER / IMMEDIATE 的 PseudoOperand，并追加 PseudoInstruction('vpush', start_addr, ...)。
    3. 单操作数 push（压 flags）生成 vpushf。

    @param p_lst 入口处的 x86 指令列表
    @param start_addr 生成的伪指令应标注的地址
    @return PseudoInstruction 列表
    """
    ret = []
    wrote_values = {}
    for inst in p_lst:
        if not inst.is_push():
            if inst.is_mov():
                wrote_values[inst.get_op_str(1)] = inst.get_op_str(2)
            continue
        print inst
        if len(inst) != 1:
            if inst.op_is_mem(1):
                if inst.is_rip_rel():
                    disp = inst.get_op_disp(1)
                    disp += inst.addr + inst.opcode_len
                    new_op = PseudoOperand(PI.MEMORY_T,
                                           '[{0:#x}]'.format(disp),
                                           inst.get_op_size(1),
                                           '', None)
                else:
                    new_op = PseudoOperand(PI.MEMORY_T,
                                           inst.get_op_str(1),
                                           inst.get_op_size(1),
                                           '', None)
                ret.append(PseudoInstruction('vpush',
                                             start_addr,
                                             [new_op]))
            elif inst.op_is_mem_abs(1):
                new_op = PseudoOperand(PI.MEMORY_T,
                                        inst.get_op_str(1),
                                        inst.get_op_size(1),
                                        '', None)
                ret.append(PseudoInstruction('vpush',
                                            start_addr,
                                            [new_op]))
            elif inst.op_is_reg(1):
                wrote_value = False
                if inst.get_op_str(1) in wrote_values:
                    new_op = PseudoOperand(PI.IMMEDIATE_T,
                                    wrote_values[inst.get_op_str(1)],
                                    inst.get_op_size(1),
                                    int(wrote_values[inst.get_op_str(1)], 16))
                    ret.append(PseudoInstruction('vpush',
                                                 start_addr,
                                                 [new_op]))
                else:
                    new_op = PseudoOperand(PI.REGISTER_T,
                                           inst.get_op_str(1),
                                           inst.get_op_size(1),
                                           inst.get_reg_name(1))
                    ret.append(PseudoInstruction('vpush',
                                                 start_addr,
                                                 [new_op]))
            elif inst.op_is_imm(1):
                new_op = PseudoOperand(PI.IMMEDIATE_T,
                                       inst.get_op_str(1),
                                       inst.get_op_size(1), '')
                ret.append(PseudoInstruction('vpush',
                                             start_addr,
                                             [new_op]))
        else:
            new_op = PseudoOperand(PI.REGISTER_T, 'flags',
                                   SV.dissassm_type, 'flags')
            p_inst = PseudoInstruction('vpushf', start_addr, [new_op])
            ret.append(p_inst)
    return ret


def make_op(inst, op, catch_value):
    """
    将单条 x86 指令的第 op 个操作数转换为对应的 PseudoOperand（内存 / 寄存器 / 立即数）。

    1. 若操作数字符串为 None，返回 None。
    2. 按 op_is_mem / op_is_reg / op_is_imm 分支构造 MEMORY_T、REGISTER_T 或 IMMEDIATE_T；内存操作数附带 catch_value。

    @param inst 含该操作数的 Instruction
    @param op 操作数编号（1 表示第一操作数）
    @param catch_value 混淆代码中捕获的关联值
    @return 对应的 PseudoOperand，无法识别时返回 None
    """
    if(inst.get_op_str(op) == None):
        return None
    if inst.op_is_mem(op):
        return PseudoOperand(PI.MEMORY_T, inst.get_op_str(op),
                            inst.get_op_size(op), inst.get_reg_name(op),
                            catch_value)
    elif inst.op_is_reg(op):
        return PseudoOperand(PI.REGISTER_T, inst.get_op_str(op),
                            inst.get_op_size(op), inst.get_reg_name(op))
    elif inst.op_is_imm(op):
        return PseudoOperand(PI.IMMEDIATE_T, inst.get_op_str(op),
                            inst.get_op_size(op), inst.get_op_value(op))
    else:
        return None


def extend_signed_catch_val(reg, catch_value):
    """
    按寄存器位宽与汇编模式（32/64 位）对 catch_value 做符号扩展，用于有符号语义下的立即数还原。

    1. 根据 reg 得到寄存器位宽 reg_size。
    2. 当值超过对应有符号正域阈值时，按 8/16/32 位分别与 0xffffff00、0xffff0000、0xffffffff00000000 等掩码组合扩展。

    @param reg 存放 catch_value 的寄存器名
    @param catch_value 从混淆代码中捕获的原始数值
    @return 符号扩展后的 catch_value
    """
    reg_size = get_size_by_reg(reg)
    if reg_size == 8 and catch_value > 0x79:
        if SV.dissassm_type == SV.ASSEMBLER_32:
            catch_value = 0xffffff00 + catch_value
        elif SV.dissassm_type == SV.ASSEMBLER_64:
            catch_value = 0xffffffffffffff00 + catch_value
        elif reg_size == 16 and catch_value > 0x7900:
            if SV.dissassm_type == SV.ASSEMBLER_32:
                catch_value = 0xffff0000 + catch_value
            elif SV.dissassm_type == SV.ASSEMBLER_64:
                catch_value = 0xffffffffffff0000 + catch_value
        elif reg_size == 32 and catch_value > 0x79000000:
            #there is nothing to do for 32bit
            if SV.dissassm_type == SV.ASSEMBLER_64:
                catch_value = 0xffffffff00000000 + catch_value
        #there is nothing to do for reg_size == 64
    return catch_value


class VmInstruction(object):
    """
    虚拟机指令类 - 将一组x86 handler指令识别为对应的虚拟指令

    handler指令被分为两类：
    - Vinstructions: 涉及ESI/RSI的指令（VM内部基础设施，如字节码指针操作）
    - Instructions: 不涉及ESI/RSI的指令（实际执行逻辑）

    识别过程通过get_pseudo_code()触发，按优先级尝试匹配各种虚拟指令模式。
    """


    def __init__(self, instr_lst, catch_value, catch_reg, inst_addr):
        """
        @param instr_lst handler中的x86指令列表
        @param catch_value 从字节码流中读取的附加参数值（catch指令获取的值）
        @param catch_reg 存放catch_value的寄存器名
        @param inst_addr 该虚拟指令在字节码中的地址
        """
        self.all_instructions = instr_lst
        self.Vinstructions = []
        self.Instructions = []
        self.is_signed = False
        for inst in instr_lst:
            if inst.is_vinst():
                self.Vinstructions.append(inst)
            else:
                self.Instructions.append(inst)
        self.Pseudocode = None
        self.catch_value = catch_value
        self.catch_reg = catch_reg
        self.addr = inst_addr
        if not self.get_pseudo_code():
            mnem_str = ''
            for inst in self.all_instructions:
                mnem_str += str(inst)
            self.Pseudocode= PI.PseudoInstruction(mnem_str, inst_addr, [], 0, PI.UNDEF_T)
            print 'Did not find pseudocode at addr: {0:#x}'.format(inst_addr)


    def __str__(self):
        if self.Pseudocode is not None:
            return str(self.Pseudocode)
        else:
            inst_str = ''
            for item in self.all_instructions:
                inst_str = inst_str + str(item) + '\n'
            return inst_str


    def replace_catch_reg(self):
        """
        @brief replace the catch_register with its catch_value
        """
        if (self.catch_reg == ''):
            return
        if self.is_signed:
            self.catch_value = extend_signed_catch_val(self.catch_reg, self.catch_value)
        self.Pseudocode.replace_reg_class(self.catch_reg, self.catch_value)


    def get_pseudo_code(self):
        """
        主调度函数：按固定优先级尝试将当前 handler 识别为已知虚拟指令，成功时写入 self.Pseudocode。

        1. 优先匹配 vpush / vpop（is_push / is_pop）；成功则调用 replace_catch_reg() 并返回 True。
        2. 否则依次尝试：vnor、vadd、vjmp、vwrite、vread、vshr、vshl、vshld、vshrd、vcall、vebp_mov、vret、vimul、vidiv。
        3. 任一 is_xxx 成功即返回 True；全部失败返回 False（由 __init__ 生成 UNDEF 伪指令）。

        @return 是否成功识别为已知虚拟指令
        """
        if (self.is_push() or
            self.is_pop()):
            self.replace_catch_reg()
            return True
        elif (self.is_nor() or
              self.is_add() or
              self.is_jmp() or
              self.is_write() or
              self.is_read() or
              self.is_shift_right() or
              self.is_shift_left() or
              self.is_shld() or
              self.is_shrd() or
              self.is_vcall() or
              self.is_mov_ebp() or
              self.is_vret() or
              self.is_imul() or
              self.is_idiv()):
            return True
        else:
            return False

###########################
#     helper functions    #
###########################

    def get_previous(self, method, pos):
        """
        在 self.Instructions 中，收集下标严格小于 pos 且 method(inst) 为真的所有指令下标（用于向前追踪数据流）。

        1. 从列表开头枚举到 pos 之前，若 method(inst) 成立则将下标加入列表。
        2. 返回下标列表，调用方通常取其中最后一个作为“最近一条”满足条件的指令。

        @param method 判定函数，签名为对单条 Instruction 返回布尔值
        @param pos 当前参考位置（不包含 pos 本身）
        @return 满足条件的指令下标列表（可能为空）
        """
        pos_lst = []
        for prev_pos, inst in enumerate(self.Instructions):
            if (prev_pos < pos) and method(inst):
                pos_lst.append(prev_pos)
        return pos_lst


    def get_subsequent(self, method, pos):
        """
        在 self.Instructions 中，收集下标严格大于 pos 且 method(inst) 为真的所有指令下标（用于向后追踪数据流）。

        1. 从 pos 之后枚举到列表末尾，若 method(inst) 成立则将下标加入列表。
        2. 返回下标列表，调用方常取第一个元素作为“最近一条”后续满足条件的指令。

        @param method 判定函数，签名为对单条 Instruction 返回布尔值
        @param pos 当前参考位置（不包含 pos 本身）
        @return 满足条件的指令下标列表（可能为空）
        """
        pos_lst = []
        for subs_pos, inst in enumerate(self.Instructions):
            if (subs_pos > pos) and method(inst):
                pos_lst.append(subs_pos)
        return pos_lst



########################
#  decision functions  #
########################
    def is_push(self):
        """
        识别 vpush：核心特征为 sub ebp（栈指针下移）配合唯一一条向栈顶写入的 mov（mov [ebp], val）。

        1. 在 self.Instructions 中向前扫描，找到 is_sub_basepointer()（sub ebp）作为压栈入口；途中若 catch 寄存器与 eax 同类且出现 cwde/cbw/cdqe，标记有符号 is_signed。
        2. 向后搜索 is_write_stack()，须恰好一条 → 确定为写栈顶的 mov，得到 push_inst 与 push_op = make_op(..., 第二操作数)。
        3. 向前搜索 is_mov()：若某 mov 读栈则判失败；若 mov 目的与 push 第二操作数寄存器类一致，则用该 mov 的源更新 push_op（追踪传播）。
        4. 读取 sub 的立即数作为 sub_value，构造 PseudoInstruction('vpush', self.addr, [push_op], sub_value)。

        @return 是否为 vpush；成功时设置 self.Pseudocode
        """
        for pos, inst in enumerate(self.Instructions):
            if(inst.is_sub_basepointer()):
                break
            if(get_reg_class(self.catch_reg) == get_reg_class('eax') and
               (inst.is_cwde() or inst.is_cbw() or inst.is_cdqe())):
                self.is_signed = True
        else : # no break
            return False
        pos_pmov_lst = self.get_subsequent(Instruction.is_write_stack, pos)
        if len(pos_pmov_lst) != 1:
            return False
        push_inst = self.Instructions[pos_pmov_lst[0]]
        pos_mov_lst = self.get_previous(Instruction.is_mov, pos)
        push_op = make_op(push_inst, 2, self.catch_value)
        for pos_mov in pos_mov_lst:
            pos_mov_inst = self.Instructions[pos_mov]
            if pos_mov_inst.is_read_stack():
                return False
            if((get_reg_class(push_inst.get_op_str(2)) ==
                  get_reg_class(pos_mov_inst.get_op_str(1))) and
                  get_reg_class(push_inst.get_op_str(2)) != None): # too strong condition
                push_op = make_op(pos_mov_inst, 2, self.catch_value)
        sub_value = self.Instructions[pos].get_op_value(2)
        self.Pseudocode = PseudoInstruction('vpush', self.addr, [push_op], sub_value)
        return True


    # control in comp.vmp loc4041c8
    # size von holen und add sub gleich?
    def is_pop(self):
        """
        识别 vpop：核心特征为 mov val, [ebp]（或等价读栈）配合 add ebp（栈指针上移）。

        1. 在 self.Instructions 中找到 is_add_basepointer()（add ebp）作为出栈入口。
        2. 向前搜索 is_read_stack()，取匹配到的最后一条作为 pop_inst；pop_op = make_op(pop_inst, 1, catch_value)。
        3. 向后搜索 is_mov()：若出现 is_write_stack() 则失败；若 mov 源与 pop 第一操作数寄存器类一致，则用该 mov 的目的更新 pop_op 并记录 op_pos。
        4. 要求最终 op_pos 处第一操作数为内存；读取 add 的立即数 add_value，构造 PseudoInstruction('vpop', ...)。

        @return 是否为 vpop；成功时设置 self.Pseudocode
        """
        for pos, inst in enumerate(self.Instructions):
            if(inst.is_add_basepointer()):
                break
        else : # no break
            return False
        pos_pmov_lst = self.get_previous(Instruction.is_read_stack, pos)
        if len(pos_pmov_lst) == 0:
            return False
        for ppos in pos_pmov_lst:
            pop_inst = self.Instructions[ppos] # get last pop_mov inst in case there are more
        pop_op = make_op(pop_inst, 1, self.catch_value)
        pos_mov_lst = self.get_subsequent(Instruction.is_mov, pos)
        op_pos = ppos
        for pos_mov in pos_mov_lst:
            pos_mov_inst = self.Instructions[pos_mov]
            if(pos_mov_inst.is_write_stack()):
                return False
            if((get_reg_class(pop_inst.get_op_str(1)) ==
                  get_reg_class(pos_mov_inst.get_op_str(2))) and
                  get_reg_class(pop_inst.get_op_str(1))):  #maybe too weak
                pop_op = make_op(pos_mov_inst, 1, self.catch_value)
                op_pos = pos_mov
        if(not self.Instructions[op_pos].op_is_mem(1)):
            return False
        add_value = self.Instructions[pos].get_op_value(2)
        self.Pseudocode = PseudoInstruction('vpop', self.addr,
                                            [pop_op], add_value)
        #print 'vpop'
        return True


    #TODO add with two regs
    def is_add(self):
        """
        识别 vadd：add 指令第二操作数非立即数，且两操作数经 mov 链与 add 的第二源寄存器对齐。

        1. 在 self.Instructions 中找到 is_add() 且第二操作数非立即数的指令。
        2. 向前 get_previous(is_mov)：查找某 mov 的第一操作数字符串与当前 add 的第二操作数字符串相同，表示第二加数来源。
        3. 构造 PseudoInstruction('vadd', self.addr, [add 的第一操作数, 该 mov 的第二操作数], 字长/8)。

        @return 是否为 vadd；成功时设置 self.Pseudocode
        """
        for pos, inst in enumerate(self.Instructions):
            if(inst.is_add() and not inst.op_is_imm(2)):
                break
        else: # no break
            return False
        pos_mov = self.get_previous(Instruction.is_mov, pos)
        # mit opstr?
        opstr = self.Instructions[pos].get_op_str(2)
        for pos0 in pos_mov:
            if opstr == self.Instructions[pos0].get_op_str(1):
                self.Pseudocode = PseudoInstruction('vadd', self.addr, 
                    [make_op(self.Instructions[pos], 1, self.catch_value),
                     make_op(self.Instructions[pos0], 2, self.catch_value)], SV.dissassm_type / 8)
                break
        else:
            return False
        return True


    def is_nor(self):
        """
        识别 vnor：典型模式为对两路操作数各 not 后再 and，对应 NOR 相关语义。

        1. 搜索双寄存器、目的与源不同的 is_and()，记录 reg0、reg1 与 and_size。
        2. 向前搜索 is_not()：累加各 not 的操作数位宽，须等于 2 * and_size（两路各一次按位宽 not）。
        3. 向前搜索 is_mov()：按寄存器类匹配 and 的两输入，必要时用更早 mov 的第二操作数替换伪指令操作数。
        4. 对 ebp 与 2 字节 and 的边界情况做操作数字符串修正；构造 PseudoInstruction('vnor', self.addr, [op1, op2], and_size)。

        @return 是否为 vnor；成功时设置 self.Pseudocode
        """
        # 1. search for and with 2 different registers
        and_found = False
        reg0 = ''
        reg1 = ''
        and_size = 0
        for pos, inst in enumerate(self.Instructions):
            if inst.is_and():
                reg0 = inst.get_reg_name(1)
                reg1 = inst.get_reg_name(2)
                and_size = inst.get_mov_size()
                if reg0 != reg1:
                    and_found = True
                    break
        if not and_found:
            return False
        pos_not = self.get_previous(Instruction.is_not, pos)
        #if len(pos_not) < 1 or len(pos_not) > 2:
        #    return False
        not_size = 0
        for posn in pos_not:
            not_size += (self.Instructions[posn].Instruction.operands[0].size / 8)
        if(not_size != 2 * and_size):
            return False
        pos_mov = self.get_previous(Instruction.is_mov, pos)
        #if len(pos_mov) != 2:
        #    return False
        mov_r0 = False
        mov_r1 = False
        op1 = make_op(self.Instructions[pos], 1, self.catch_value)
        op2 = make_op(self.Instructions[pos], 2, self.catch_value)
        for pos_reg0 in pos_mov:
            if (get_reg_class(reg0) ==
                  get_reg_class(self.Instructions[pos_reg0].get_reg_name(1))):
                mov_r0 = True
                break
        for pos_reg1 in pos_mov:
            if (get_reg_class(reg1) ==
                  get_reg_class(self.Instructions[pos_reg1].get_reg_name(1))):
                mov_r1 = True
                break
        if mov_r0:
            op1 = make_op(self.Instructions[pos_reg0], 2, self.catch_value)
        if mov_r1:
            op2 = make_op(self.Instructions[pos_reg1], 2, self.catch_value)
        #quick fix correct !!!
        if(op1.register == 'ebp') and (and_size == 2):
            op1 = op1.replace('+0x4', '+0x2')
        self.Pseudocode = PseudoInstruction('vnor', self.addr, [op1, op2], and_size)
        return True


    def is_jmp(self):
        """
        识别 vjmp：在完整 handler（含 Vinstructions）上匹配“更新指令指针（ESI/RSI）”与“add ebp”组合。

        1. 在 self.all_instructions 中查找 is_add_basepointer()（add ebp），定位栈平衡位置 pos。
        2. 从序列开头向后扫描至 pos 之前，找到 is_isp_mov()（写入 VM 指令指针寄存器的 mov），提取新指针来源操作数。
        3. 读取 add ebp 的立即数 add_value，构造 PseudoInstruction('vjmp', self.addr, [make_op(isp_mov, 2, catch_value)], add_value)。

        @return 是否为 vjmp；成功时设置 self.Pseudocode
        """
        for pos, inst in enumerate(self.all_instructions):
            if(inst.is_add_basepointer()):
                break
        else : # no break
            return False
        prev_pos = 0
        while prev_pos < pos:
            if self.all_instructions[prev_pos].is_isp_mov():
                break
            prev_pos = prev_pos + 1
        else: # no break
            return False
        add_value = self.all_instructions[pos].get_op_value(2)
        self.Pseudocode = PseudoInstruction(
                    'vjmp', self.addr,
                    [make_op(self.all_instructions[prev_pos], 2, self.catch_value)], add_value)
        return True

    def is_write(self):
        """
        识别 vwrite：向非 VM 栈内存写入（第一操作数为内存且非 is_write_stack()），并追踪地址与数据源的 mov 链。

        1. 在 self.all_instructions 中查找 op_is_mem(1) 且非 is_write_stack() 的 mov，得到目的内存寄存器 reg0、源 reg1 与 mov_size。
        2. 在 self.Instructions 中查找 is_add_basepointer()，得到与栈相关的 sub_size（add 立即数）。
        3. 向前 get_previous(is_mov)：分别按寄存器类匹配 reg0、reg1，构造 REFERENCE 型地址操作数与数据操作数。
        4. 构造 PseudoInstruction('vwrite', self.addr, [op1, op2], mov_size, PI.WRITE_T, PI.IN2_OUT0, sub_size)。

        @return 是否为 vwrite；成功时设置 self.Pseudocode
        """
        reg0 = ''
        reg1 = ''
        mov_size = 0
        sub_size = 0
        for pos, inst in enumerate(self.all_instructions):
            if inst.op_is_mem(1) and not inst.is_write_stack():
                reg0 = inst.get_reg_name(1)
                reg1 = inst.get_reg_name(2)
                mov_size = inst.get_mov_size()
                break
        else: # no break
            return False
        for subpos, inst in enumerate(self.Instructions):
            if(inst.is_add_basepointer()):
                sub_size = inst.get_op_value(2)
                break
        else : # no break
            return False
        pos_mov = self.get_previous(Instruction.is_mov, pos)
        mov_r0 = False
        mov_r1 = False
        for pos_reg0 in pos_mov:
            if (get_reg_class(reg0) ==
                  get_reg_class(self.Instructions[pos_reg0].get_reg_name(1))):
                mov_r0 = True
                break
        for pos_reg1 in pos_mov:
            if (get_reg_class(reg1) ==
                  get_reg_class(self.Instructions[pos_reg1].get_reg_name(1))):
                mov_r1 = True
                break
        if mov_r0 and mov_r1:
            op1_inst =  self.Instructions[pos_reg0]
            op1 = PseudoOperand(PI.REFERENCE_T, op1_inst.get_op_str(2),
                                op1_inst.get_op_size(2), op1_inst.get_reg_name(2))
            op2 = make_op(self.Instructions[pos_reg1], 2, self.catch_value)
            self.Pseudocode = PseudoInstruction('vwrite', self.addr,
                        [op1, op2], mov_size, PI.WRITE_T, PI.IN2_OUT0, sub_size)
            return True
        else:
            return False


    def is_read(self):
        """
        识别 vread：从非 VM 栈内存读取（第二操作数为内存且非 is_read_stack()），并连接读前/读后的 mov。

        1. 在 self.all_instructions 中查找 op_is_mem(2) 且非 is_read_stack() 的 mov，记录 reg0、reg1、mov_size。
        2. 向前 get_previous(is_mov)：匹配内存源寄存器类与某 mov 目的寄存器类，确定地址引用来自哪条 mov。
        3. 向后 get_subsequent(is_mov)：匹配目的寄存器类与 reg0，得到写回寄存器及 push_size。
        4. 构造 PseudoInstruction('vread', self.addr, [op1, op2], mov_size, PI.READ_T, PI.IN1_OUT1, push_size)。

        @return 是否为 vread；成功时设置 self.Pseudocode
        """
        reg0 = ''
        reg1 = ''
        mov_size = 0
        for pos, inst in enumerate(self.all_instructions):
            if inst.op_is_mem(2) and not inst.is_read_stack():
                reg0 = inst.get_reg_name(1)
                reg1 = inst.get_reg_name(2)
                mov_size = inst.get_mov_size()
                break
        else: # no break
            return False
        prev_mov = self.get_previous(Instruction.is_mov, pos)
        post_mov = self.get_subsequent(Instruction.is_mov, pos)
        for prev_pos in prev_mov:
            if(get_reg_class(reg1) ==
               get_reg_class(self.Instructions[prev_pos].get_reg_name(1))):
                break
        else: # no break
            return False
        for post_pos in post_mov:
            if(get_reg_class(reg0) ==
               get_reg_class(self.Instructions[post_pos].get_reg_name(2))):
                push_size = self.Instructions[post_pos].get_mov_size()
                break
        else: # no break
            return False
        # wta = write to address
        #if mov_size == 1:
        op1 = make_op(self.Instructions[post_pos], 1, self.catch_value)
        op2_inst = self.Instructions[prev_pos]
        op2 = PseudoOperand(PI.REFERENCE_T, op2_inst.get_op_str(2),
                            op2_inst.get_op_size(2), op2_inst.get_reg_name(2))
        self.Pseudocode = PseudoInstruction('vread', self.addr,
                                            [op1, op2], mov_size, PI.READ_T, PI.IN1_OUT1 , push_size)
        return True
        

    def is_shift_right(self):
        """
        识别 vshr：双寄存器 shr（目的与移位计数寄存器不同），并校验前后 mov 溯源与结果写回。

        1. 在 self.Instructions 中查找 is_shr() 且两操作数均为寄存器、且 reg0 != reg1。
        2. 向前 get_previous(is_mov)：须恰好两条，分别匹配两 shr 操作数寄存器类，得到操作数来源。
        3. 向后 get_subsequent(is_mov)：找到将结果写回与 shr 第一操作数同类寄存器的 mov，得到 ret_size。
        4. 构造 PseudoInstruction('vshr', self.addr, [op0, op1], ret_size)。

        @return 是否为 vshr；成功时设置 self.Pseudocode
        """
        # 1. search for and with 2 different registers
        and_found = False
        reg0 = ''
        reg1 = ''
        for pos, inst in enumerate(self.Instructions):
            if inst.is_shr() and inst.op_is_reg(1) and inst.op_is_reg(2):
                reg0 = inst.get_reg_name(1)
                reg1 = inst.get_reg_name(2)
                if reg0 != reg1:
                    and_found = True
                    break
        if not and_found:
            return False
        pos_mov = self.get_previous(Instruction.is_mov, pos)
        if len(pos_mov) != 2:
            return False
        mov_r0 = False
        mov_r1 = False
        for pos_reg0 in pos_mov:
            if (get_reg_class(reg0) ==
                  get_reg_class(self.Instructions[pos_reg0].get_reg_name(1))):
                mov_r0 = True
                break
        for pos_reg1 in pos_mov:
            if (get_reg_class(reg1) ==
                  get_reg_class(self.Instructions[pos_reg1].get_reg_name(1))):
                mov_r1 = True
                break
        post_mov = self.get_subsequent(Instruction.is_mov, pos)
        for save_mov in post_mov:
            if (get_reg_class(reg0) ==
                  get_reg_class(self.Instructions[save_mov].get_reg_name(2))):
                ret_size = self.Instructions[save_mov].get_mov_size()
                break
        else: # no break
            return False
        if mov_r0 and mov_r1:
            # TODO byte word usw...
            self.Pseudocode = PseudoInstruction('vshr', self.addr,
                [make_op(self.Instructions[pos_reg0], 2, self.catch_value),
                 make_op(self.Instructions[pos_reg1], 2, self.catch_value)],
                ret_size)
            return True
        else:
            return False


    def is_shift_left(self):
        """
        识别 vshl：双寄存器 shl（目的与移位计数寄存器不同），并校验前后 mov 溯源与结果写回。

        1. 在 self.Instructions 中查找 is_shl() 且两操作数均为寄存器、且 reg0 != reg1。
        2. 向前 get_previous(is_mov)：须恰好两条，分别匹配两 shl 操作数寄存器类。
        3. 向后 get_subsequent(is_mov)：找到将结果写回与 shl 第一操作数同类寄存器的 mov，得到 ret_size。
        4. 构造 PseudoInstruction('vshl', self.addr, [op0, op1], ret_size)。

        @return 是否为 vshl；成功时设置 self.Pseudocode
        """
        # 1. search for and with 2 different registers
        and_found = False
        reg0 = ''
        reg1 = ''
        for pos, inst in enumerate(self.Instructions):
            if inst.is_shl() and inst.op_is_reg(1) and inst.op_is_reg(2):
                reg0 = inst.get_reg_name(1)
                reg1 = inst.get_reg_name(2)
                if reg0 != reg1:
                    and_found = True
                    break
        if not and_found:
            return False
        pos_mov = self.get_previous(Instruction.is_mov, pos)
        if len(pos_mov) != 2:
            return False
        mov_r0 = False
        mov_r1 = False
        for pos_reg0 in pos_mov:
            if (get_reg_class(reg0) ==
                  get_reg_class(self.Instructions[pos_reg0].get_reg_name(1))):
                mov_r0 = True
                break
        for pos_reg1 in pos_mov:
            if (get_reg_class(reg1) ==
                  get_reg_class(self.Instructions[pos_reg1].get_reg_name(1))):
                mov_r1 = True
                break
        post_mov = self.get_subsequent(Instruction.is_mov, pos)
        for save_mov in post_mov:
            if (get_reg_class(reg0) ==
                  get_reg_class(self.Instructions[save_mov].get_reg_name(2))):
                ret_size = self.Instructions[save_mov].get_mov_size()
                break
        else: # no break
            return False
        if mov_r0 and mov_r1:
            # TODO byte word usw...
            self.Pseudocode = PseudoInstruction('vshl', self.addr,
                [make_op(self.Instructions[pos_reg0], 2, self.catch_value),
                 make_op(self.Instructions[pos_reg1], 2, self.catch_value)],
                ret_size)
            return True
        else:
            return False


    def is_shrd(self):
        """
        识别 vshrd：三操作数 shrd（双精度右移），三个寄存器操作数且第一与第二不同。

        1. 在 self.Instructions 中查找 is_shrd() 且三个操作数均为寄存器，reg0 != reg1，记录 reg0/reg1/reg2。
        2. 向前 get_previous(is_mov)：分别找到目的寄存器类与 reg0、reg1、reg2 匹配的三条 mov，取各 mov 的第二操作数作为虚拟操作数来源。
        3. 构造 PseudoInstruction('vshrd', self.addr, [三个 make_op(..., 2, catch_value)])。

        @return 是否为 vshrd；成功时设置 self.Pseudocode
        """
        and_found = False
        reg0 = ''
        reg1 = ''
        reg2 = ''
        for pos, inst in enumerate(self.Instructions):
            if (inst.is_shrd() and inst.op_is_reg(1) and inst.op_is_reg(2)
                  and inst.op_is_reg(3)):
                reg0 = inst.get_reg_name(1)
                reg1 = inst.get_reg_name(2)
                reg2 = inst.get_reg_name(3)
                if reg0 != reg1:
                    and_found = True
                    break
        if not and_found:
            return False
        prev_mov = self.get_previous(Instruction.is_mov, pos)
        for prev_pos0 in prev_mov:
            if (get_reg_class(reg0) ==
                  get_reg_class(self.Instructions[prev_pos0].get_reg_name(1))):
                break
        else: # no break
            return False
        for prev_pos1 in prev_mov:
            if (get_reg_class(reg1) ==
                  get_reg_class(self.Instructions[prev_pos1].get_reg_name(1))):
                break
        else: # no break
            return False
        for prev_pos2 in prev_mov:
            if (get_reg_class(reg2) ==
                  get_reg_class(self.Instructions[prev_pos2].get_reg_name(1))):
                break
        else: # no break
            return False
        self.Pseudocode = PseudoInstruction('vshrd', self.addr,
                [make_op(self.Instructions[prev_pos0], 2, self.catch_value),
                 make_op(self.Instructions[prev_pos1], 2, self.catch_value),
                 make_op(self.Instructions[prev_pos2], 2, self.catch_value)])
        return True

    def is_shld(self):
        """
        识别 vshld：三操作数 shld（双精度左移），三个寄存器操作数且第一与第二不同。

        1. 在 self.Instructions 中查找 is_shld() 且三个操作数均为寄存器，reg0 != reg1，记录 reg0/reg1/reg2。
        2. 向前 get_previous(is_mov)：分别匹配三条 mov 的目的与三个 shld 寄存器类，取第二操作数作为虚拟操作数。
        3. 构造 PseudoInstruction('vshld', self.addr, [三个 make_op(..., 2, catch_value)])。

        @return 是否为 vshld；成功时设置 self.Pseudocode
        """
        and_found = False
        reg0 = ''
        reg1 = ''
        reg2 = ''
        for pos, inst in enumerate(self.Instructions):
            if (inst.is_shld() and inst.op_is_reg(1) and inst.op_is_reg(2)
                  and inst.op_is_reg(3)):
                reg0 = inst.get_reg_name(1)
                reg1 = inst.get_reg_name(2)
                reg2 = inst.get_reg_name(3)
                if reg0 != reg1:
                    and_found = True
                    break
        if not and_found:
            return False
        prev_mov = self.get_previous(Instruction.is_mov, pos)
        for prev_pos0 in prev_mov:
            if (get_reg_class(reg0) ==
                  get_reg_class(self.Instructions[prev_pos0].get_reg_name(1))):
                break
        else: # no break
            return False
        for prev_pos1 in prev_mov:
            if (get_reg_class(reg1) ==
                  get_reg_class(self.Instructions[prev_pos1].get_reg_name(1))):
                break
        else: # no break
            return False
        for prev_pos2 in prev_mov:
            if (get_reg_class(reg2) ==
                  get_reg_class(self.Instructions[prev_pos2].get_reg_name(1))):
                break
        else: # no break
            return False
        self.Pseudocode = PseudoInstruction('vshld', self.addr,
                [make_op(self.Instructions[prev_pos0], 2, self.catch_value),
                 make_op(self.Instructions[prev_pos1], 2, self.catch_value),
                 make_op(self.Instructions[prev_pos2], 2, self.catch_value)])
        return True


    def is_vcall(self):
        """
        识别 vcall：handler 中出现 call 指令，并尽量通过向前 mov 链解析调用目标操作数。

        1. 在 self.Instructions 中查找 is_call()。
        2. 默认取 call 的第一操作数字符串；向前 get_previous(is_mov)：若某 mov 目的寄存器类与 call 目标寄存器类一致，则用 make_op(mov, 2) 作为真实目标操作数。
        3. 构造 PseudoInstruction('vcall', self.addr, [op1])。

        @return 是否为 vcall；成功时设置 self.Pseudocode
        """
        for pos, inst in enumerate(self.Instructions):
            if(inst.is_call()):
                break
        else : # no break
            return False
        op1 = self.Instructions[pos].get_op_str(1)
        prev_mov = self.get_previous(Instruction.is_mov, pos)
        for prev_pos in prev_mov:
            if (get_reg_class(self.Instructions[pos].get_reg_name(1)) ==
                get_reg_class(self.Instructions[prev_pos].get_reg_name(1))):
                    op1 = make_op(self.Instructions[prev_pos], 2, self.catch_value)
        self.Pseudocode = PseudoInstruction('vcall', self.addr, [op1])
        return True


    def is_vret(self):
        """
        识别 vret：handler 中出现 ret 指令，对应虚拟机“返回”语义（具体 pop 展开由 add_ret_pop 处理）。

        1. 在 self.Instructions 中查找 is_ret()。
        2. 构造无操作数的 PseudoInstruction('vret', self.addr)。

        @return 是否为 vret；成功时设置 self.Pseudocode
        """
        for pos, inst in enumerate(self.Instructions):
            if(inst.is_ret()):
                break
        else : # no break
            return False
        self.Pseudocode = PseudoInstruction('vret', self.addr)
        return True


    def is_mov_ebp(self):
        """
        识别 vebp_mov：mov 的两操作数经寄存器类判断均属于 ebp/rbp 一类（栈基址在 VM 句柄间的传递或同步）。

        1. 在 self.Instructions 中查找 is_mov()，且 get_reg_class(目的) 与 get_reg_class(源) 均为 ebp 类。
        2. 对两个操作数分别 make_op(inst, 1/2, catch_value)。
        3. 构造 PseudoInstruction('vebp_mov', self.addr, [op1, op2])。

        @return 是否为 vebp_mov；成功时设置 self.Pseudocode
        """
        op1 = ''
        op2 = ''
        for pos, inst in enumerate(self.Instructions):
            if(inst.is_mov() and
               get_reg_class(inst.get_reg_name(1)) == get_reg_class('ebp') and
               get_reg_class(inst.get_reg_name(2)) == get_reg_class('ebp')):
                op1 = make_op(inst, 1, self.catch_value)
                op2 = make_op(inst, 2, self.catch_value)
                break
        else : # no break
            return False
        self.Pseudocode = PseudoInstruction('vebp_mov', self.addr, [op1, op2])
        return True


    def is_imul(self):
        """
        识别 vimul：有符号乘法 imul，双寄存器情形（含隐式 eax 的另一乘数），并向前 mov 溯源两路输入。

        1. 在 self.Instructions 中查找 is_imul() 且第一操作数为寄存器；若仅单操作数则第二乘数取当前模式下的 eax 对应寄存器名；要求两寄存器不同。
        2. 向前 get_previous(is_mov)：分别匹配两乘数寄存器类与 mov 目的，得到 mov_r0、mov_r1。
        3. 构造 PseudoInstruction('vimul', self.addr, [两路 make_op(..., 2)], 字长/8, PI.IMUL_T, PI.IN2_OUT3)。

        @return 是否为 vimul；成功时设置 self.Pseudocode
        """
        reg0 = ''
        reg1 = ''
        mul_found = False
        for pos, inst in enumerate(self.Instructions):
            if (inst.is_imul() and inst.op_is_reg(1)):
                reg0 = inst.get_reg_name(1)
                if inst.get_reg_name(2) == None:
                    reg1 = get_reg_by_size(get_reg_class('eax'), SV.dissassm_type)
                else:
                    reg1 = inst.get_reg_name(2)
                if reg0 != reg1:
                    mul_found = True
                    break
        if not mul_found:
            return False
        pos_mov = self.get_previous(Instruction.is_mov, pos)
        for pos_reg0 in pos_mov:
            if (get_reg_class(reg0) ==
                  get_reg_class(self.Instructions[pos_reg0].get_reg_name(1))):
                mov_r0 = True
                break
        for pos_reg1 in pos_mov:
            if (get_reg_class(reg1) ==
                  get_reg_class(self.Instructions[pos_reg1].get_reg_name(1))):
                mov_r1 = True
                break
        if mov_r0 and mov_r1:
            self.Pseudocode = PseudoInstruction('vimul', self.addr,
                [make_op(self.Instructions[pos_reg0], 2, self.catch_value),
                 make_op(self.Instructions[pos_reg1], 2, self.catch_value)],
                SV.dissassm_type / 8, PI.IMUL_T, PI.IN2_OUT3)
            return True
        else:
            return False


    def is_idiv(self):
        """
        识别 vidiv：有符号除法 idiv，被除数隐含为 eax/edx 体系，除数为 idiv 的单内存或寄存器操作数。

        1. 在 self.Instructions 中查找 is_idiv()；reg0、reg1 固定为当前模式下 eax、edx 对应寄存器名，op_name 为除数操作数字符串。
        2. 向前 get_previous(is_mov)：分别匹配 eax 类、edx 类目的寄存器的 mov，得到被除数高/低部分的来源。
        3. 构造 PseudoInstruction('vidiv', self.addr, [两路 mov 源, idiv 除数操作数], 字长/8, PI.DIV_T, PI.IN3_OUT3)。

        @return 是否为 vidiv；成功时设置 self.Pseudocode
        """
        reg0 = ''
        reg1 = ''
        op_name = ''
        div_found = False
        for pos, inst in enumerate(self.Instructions):
            if (inst.is_idiv()):
                reg0 = get_reg_by_size(get_reg_class('eax'), SV.dissassm_type)
                reg1 = get_reg_by_size(get_reg_class('edx'), SV.dissassm_type)
                op_name = inst.get_op_str(1)
                div_found = True
        if not div_found:
            return False
        pos_mov = self.get_previous(Instruction.is_mov, pos)
        for pos_reg0 in pos_mov:
            if (get_reg_class(reg0) ==
                  get_reg_class(self.Instructions[pos_reg0].get_reg_name(1))):
                mov_r0 = True
                break
        for pos_reg1 in pos_mov:
            if (get_reg_class(reg1) ==
                  get_reg_class(self.Instructions[pos_reg1].get_reg_name(1))):
                mov_r1 = True
                break
        if mov_r0 and mov_r1:
            self.Pseudocode = PseudoInstruction('vidiv', self.addr,
                [make_op(self.Instructions[pos_reg0], 2, self.catch_value),
                 make_op(self.Instructions[pos_reg1], 2, self.catch_value),
                 make_op(self.Instructions[pos], 1, self.catch_value)],
                SV.dissassm_type / 8, PI.DIV_T, PI.IN3_OUT3)
            return True
        else:
            return False