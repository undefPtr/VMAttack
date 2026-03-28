# -*- coding: utf-8 -*-
"""
x86/x64 指令适配层 (Adapter Pattern)

将 distorm3 反汇编引擎输出的原始 DecomposedInst 封装为面向对象的 Instruction，
提供 30+ 语义查询方法供 VmInstruction 模式匹配使用。

distorm3 限制:
- 已停止维护，仅支持 32-bit Python（IDA 6.8 可用，IDA 7.0+ 不可用）
- 若需迁移到 64-bit Python / IDA 7.x+，需替换为 capstone

@author: Tobias
"""
import distorm3

from lib import StartVal as SV

class Instruction(object):
    """
    distorm3 指令的适配器包装类。

    核心职责：
    1. 将 distorm3.Decompose() 返回的底层指令对象包装为统一接口
    2. 提供 is_xxx() 系列方法，按语义分类查询指令类型
    3. 提供 get_xxx() 系列方法，提取操作数的寄存器名/大小/值/位移
    4. 提供 op_is_xxx() 系列方法，判断操作数的类型（寄存器/立即数/内存）

    方法分类：
    ├── 指令类型判断: is_mov/add/and/not/shr/shl/push/pop/ret/call/...
    ├── MOV 大小判断: is_byte_mov/word_mov/double_mov/quad_mov + get_mov_size
    ├── VM 语义查询: is_catch_instr/is_vinst/is_isp_mov
    ├── 栈操作判断: is_write_stack/is_read_stack/is_mov_basep_stackp
    ├── 操作数类型: op_is_reg/op_is_imm/op_is_mem/op_is_mem_abs
    └── 操作数提取: get_op_str/get_op_size/get_reg_name/get_op_value/get_op_disp/get_op
    """

    def __init__(self, offset, code, type=distorm3.Decode32Bits, feature=0):
        """
        反汇编单条指令并包装为 Instruction 对象。

        :param offset: 指令的虚拟地址 (int)
        :param code: 指令的原始机器码字节 (str/bytes)
        :param type: 解码模式，由 SV.dissassm_type 覆盖（32→Decode32Bits / 64→Decode64Bits）
        :param feature: distorm3 特性标志，目前未使用
        """
        self.valid = False
        if SV.dissassm_type == 64:
            type = distorm3.Decode64Bits
        else:
            type = distorm3.Decode32Bits
        inst = distorm3.Decompose(offset, code, type, feature)
        if len(inst) == 1:
            self.Instruction = inst[0]
            if self.Instruction.valid:
                self.valid = True
        self.opcode_len = len(code)
        self.opcode_bytes = []
        self.addr = offset
        for x in code:
            self.opcode_bytes.append(ord(x))
        self._len = len(self.Instruction.operands) + 1 


    def __str__(self):
        """返回指令的小写字符串表示，如 'mov eax, [esi]'。"""
        return str(self.Instruction).lower()


    def __len__(self):
        """返回操作数个数 + 1（含助记符本身），与 VmInstruction 的 len() 语义对齐。"""
        return self._len


    def is_catch_instr(self):
        """
        判断是否为 VM 的"catch 指令"——从字节码流中读取额外参数。

        catch 指令的特征：
        1. 必须是 mov 指令且有 2 个操作数
        2. 源操作数(op1)为内存类型，且基址寄存器为 ESI/RSI（VM 指令指针）
        3. 目的操作数(op0)为寄存器类型

        示例：mov eax, [esi] — 从 VM 字节码流读取一个值到 eax

        :return: True 若为 catch 指令，否则 False
        """
        if len(self.Instruction.operands) != 2:
            return False
        if (self.is_mov() and
            self.Instruction.operands[1].type == distorm3.OPERAND_MEMORY and
            self.Instruction.operands[0].type == distorm3.OPERAND_REGISTER):
            reg_index = self.Instruction.operands[1].index 
            if reg_index != None:
                reg_name = distorm3.Registers[reg_index]
                #change to reverserers input
                if('ESI' in reg_name or 'RSI' in reg_name):
                    return True
                else:
                    return False
            else:
                return False
        else:
            return False



    def is_mov(self):
        """
        判断是否为 mov 类指令（含 movzx/movsx 等变体）。
        条件：助记符包含 'MOV' 且指令类别为整数运算（ISC_INTEGER）。
        """
        mnem = distorm3.Mnemonics[self.Instruction.opcode]
        return ('MOV' in mnem) and (self.Instruction.instructionClass == 'ISC_INTEGER')


    def is_byte_mov(self):
        """
        判断是否为单字节(8-bit) mov，如 mov al, [esi]。
        任一操作数大小为 8 位即返回 True。
        """
        #both operands must exist
        if len(self.Instruction.operands) != 2:
            return False
        return (self.Instruction.operands[0].size == 8 or
                                  self.Instruction.operands[1].size == 8)


    def is_word_mov(self):
        """
        判断是否为双字节(16-bit) mov，如 mov ax, [esi]。
        任一操作数为 16 位、且另一操作数 ≥16 位即返回 True。
        """
        #both operands must exist
        if len(self.Instruction.operands) != 2:
           return False
        sizeOp1 = self.Instruction.operands[0].size
        sizeOp2 = self.Instruction.operands[1].size
        if (sizeOp1 == 16 and sizeOp2 >= 16):
            return True
        elif (sizeOp1 >= 16 and sizeOp2 == 16):
            return True
        else:
            return False



    def is_double_mov(self):
        """
        判断是否为四字节(32-bit) mov，如 mov eax, [esi]。
        任一操作数为 32 位、且另一操作数 ≥32 位即返回 True。
        """
        #both operands must exist
        if len(self.Instruction.operands) != 2:
            return False
        sizeOp1 = self.Instruction.operands[0].size
        sizeOp2 = self.Instruction.operands[1].size
        if (sizeOp1 == 32 and sizeOp2 >= 32):
            return True
        elif (sizeOp1 >= 32 and sizeOp2 == 32):
            return True
        else:
            return False


    def is_quad_mov(self):
        """
        判断是否为八字节(64-bit) mov，如 mov rax, [rsi]。
        任一操作数为 64 位、且另一操作数 ≥64 位即返回 True。
        """
        #both operands must exist
        if len(self.Instruction.operands) != 2:
            return False
        sizeOp1 = self.Instruction.operands[0].size
        sizeOp2 = self.Instruction.operands[1].size
        if (sizeOp1 == 64 and sizeOp2 >= 64):
            return True
        elif (sizeOp1 >= 64 and sizeOp2 == 64):
            return True
        else:
            return False


    def get_mov_size(self):
        """
        获取 mov 传输的字节数。

        :return: 8/4/2/1 分别对应 quad/double/word/byte mov，无法判断返回 None
        """
        if self.is_quad_mov():
            return 8
        elif self.is_double_mov():
            return 4
        elif self.is_word_mov():
            return 2
        elif self.is_byte_mov():
            return 1
        else:
            return None


    def get_size(self):
        """获取指令的机器码长度（字节数），委托给 distorm3 的 size 属性。"""
        return self.Instruction.size


    def is_mov_basep_stackp(self):
        """
        判断是否为 'mov ebp, esp' 或 'mov rbp, rsp'。
        此指令是函数/VM handler 入口处建立栈帧的标志性操作。
        """
        if len(self.Instruction.operands) != 2:
            return False
        Op0 = self.Instruction.operands[0]
        Op1 = self.Instruction.operands[1]
        if (Op0.type == distorm3.OPERAND_REGISTER and
            Op1.type == distorm3.OPERAND_REGISTER and
            (Op0.name == 'EBP' or Op0.name == 'RBP') and
            (Op1.name == 'ESP' or Op1.name == 'RSP')):
            return True
        else:
            return False

    def is_write_stack(self):
        """
        判断是否为向 VM 栈写入的指令。
        条件：mov 且目的操作数为以 EBP/RBP 为基址、位移为 0 的内存引用。
        即 'mov [ebp], xxx' 形式，对应 VM 的 vpush 操作。
        """
        if len(self.Instruction.operands) != 2:
            return False
        op0 = self.Instruction.operands[0]
        if op0.index == None or op0.disp != 0:
            return False
        if (self.is_mov() and
            op0.type == distorm3.OPERAND_MEMORY and
            (distorm3.Registers[op0.index] == 'EBP' or
             distorm3.Registers[op0.index] == 'RBP')):
            return True
        else:
            return False


    def is_read_stack(self):
        """
        判断是否为从 VM 栈读取的指令。
        条件：mov 且源操作数为以 EBP/RBP 为基址、位移为 0 的内存引用。
        即 'mov xxx, [ebp]' 形式，对应 VM 的 vpop 操作。
        """
        if len(self.Instruction.operands) != 2:
            return False
        op1 = self.Instruction.operands[1]
        if op1.index == None or op1.disp != 0:
            return False
        if (self.is_mov() and
            op1.type == distorm3.OPERAND_MEMORY and
            (distorm3.Registers[op1.index] == 'EBP' or
             distorm3.Registers[op1.index] == 'RBP')):
            return True
        else:
            return False


    def is_isp_mov(self):
        """
        判断是否为 VM 指令指针(ISP)更新操作。
        条件：mov 且目的操作数为 ESI/RSI 寄存器。
        ESI/RSI 在此 VM 实现中充当字节码流指针，更新它意味着跳转到新的 VM 指令。
        """
        if len(self.Instruction.operands) != 2:
            return False
        op0 = self.Instruction.operands[0]
        if op0.index == None:
            return False
        if (self.is_mov() and
            op0.type == distorm3.OPERAND_REGISTER and
            (distorm3.Registers[op0.index] == 'ESI' or
             distorm3.Registers[op0.index] == 'RSI')):
            return True
        else:
            return False


    def op_is_reg(self, op):
        """
        判断指定操作数是否为寄存器类型。

        :param op: 操作数编号，1-based（第1个操作数传1，第2个传2）
        :return: True 若为寄存器类型（OPERAND_REGISTER）
        """
        if op < 1 or op > len(self.Instruction.operands):
            return False
        return self.Instruction.operands[op-1].type == distorm3.OPERAND_REGISTER


    def op_is_imm(self, op):
        """
        判断指定操作数是否为立即数类型。

        :param op: 操作数编号，1-based
        :return: True 若为立即数类型（OPERAND_IMMEDIATE）
        """
        if op < 1 or op > len(self.Instruction.operands):
            return False
        return self.Instruction.operands[op-1].type == distorm3.OPERAND_IMMEDIATE


    def op_is_mem(self, op):
        """
        判断指定操作数是否为内存访问类型（基址+偏移形式，如 [ebp+4]）。

        :param op: 操作数编号，1-based
        :return: True 若为内存访问类型（OPERAND_MEMORY）
        """
        if op < 1 or op > len(self.Instruction.operands):
            return False
        return self.Instruction.operands[op-1].type == distorm3.OPERAND_MEMORY


    def op_is_mem_abs(self, op):
        """
        判断指定操作数是否为绝对地址内存访问（如 [0x401000]）。

        :param op: 操作数编号，1-based
        :return: True 若为绝对地址内存访问（OPERAND_ABSOLUTE_ADDRESS）
        """
        if op < 1 or op > len(self.Instruction.operands):
            return False
        return self.Instruction.operands[op-1].type == distorm3.OPERAND_ABSOLUTE_ADDRESS


    def is_vinst(self):
        """
        判断是否为 VM 相关指令——任一操作数涉及 ESI/RSI。

        ESI/RSI 是 VM 字节码指针，任何读写 ESI/RSI 的指令都与 VM 执行密切相关。
        支持检测寄存器直接引用和内存间接引用两种形式。
        """
        for op in self.Instruction.operands:
            if op.type == distorm3.OPERAND_REGISTER:
                if op.name == 'ESI' or op.name == 'RSI':
                    return True
            elif op.type == distorm3.OPERAND_MEMORY:
                if op.index != None:
                    if (distorm3.Registers[op.index] == 'ESI' or
                        distorm3.Registers[op.index] == 'RSI'):
                        return True
        return False


    def is_ret(self):
        """判断是否为 ret 指令（流控制类型为 FC_RET）。"""
        return self.Instruction.flowControl == 'FC_RET'


    def is_call(self):
        """判断是否为 call 指令（助记符以 CALL 开头且为整数运算类）。"""
        return (self.Instruction.mnemonic.startswith('CALL') and
                self.Instruction.instructionClass == 'ISC_INTEGER')


    def is_and(self):
        """判断是否为 and 逻辑与指令。"""
        return (self.Instruction.mnemonic.startswith('AND') and
                self.Instruction.instructionClass == 'ISC_INTEGER')


    def is_shr(self):
        """判断是否为 shr 逻辑右移指令。"""
        return (self.Instruction.mnemonic == 'SHR' and
                self.Instruction.instructionClass == 'ISC_INTEGER')


    def is_shl(self):
        """判断是否为 shl 逻辑左移指令。"""
        return (self.Instruction.mnemonic == 'SHL' and
                self.Instruction.instructionClass == 'ISC_INTEGER')


    def is_shld(self):
        """判断是否为 shld 双精度左移指令。"""
        return (self.Instruction.mnemonic == 'SHLD' and
                self.Instruction.instructionClass == 'ISC_INTEGER')


    def is_shrd(self):
        """判断是否为 shrd 双精度右移指令。"""
        return (self.Instruction.mnemonic == 'SHRD' and
                self.Instruction.instructionClass == 'ISC_INTEGER')


    def is_cwde(self):
        """判断是否为 cwde 符号扩展指令（将 ax 符号扩展到 eax）。"""
        return self.Instruction.mnemonic == 'CWDE'


    def is_cbw(self):
        """判断是否为 cbw 符号扩展指令（将 al 符号扩展到 ax）。"""
        return self.Instruction.mnemonic == 'CBW'


    def is_cdqe(self):
        """判断是否为 cdqe 符号扩展指令（将 eax 符号扩展到 rax，仅64位模式）。"""
        return self.Instruction.mnemonic == 'CDQE'

    def is_imul(self):
        """判断是否为 imul 有符号乘法指令。"""
        return self.Instruction.mnemonic == 'IMUL'


    def is_idiv(self):
        """判断是否为 idiv 有符号除法指令。"""
        return self.Instruction.mnemonic == 'IDIV'


    def is_add(self):
        """判断是否为 add 加法指令。"""
        return (self.Instruction.mnemonic.startswith('ADD') and
                self.Instruction.instructionClass == 'ISC_INTEGER')


    def is_not(self):
        """判断是否为 not 按位取反指令。"""
        return (self.Instruction.mnemonic.startswith('NOT') and
                self.Instruction.instructionClass == 'ISC_INTEGER')


    def is_pop(self):
        """判断是否为 pop 或 popf（弹出标志寄存器）指令。"""
        return (self.Instruction.mnemonic == 'POP' or
                self.Instruction.mnemonic == 'POPF')


    def is_push(self):
        """判断是否为 push 或 pushf（压入标志寄存器）指令。"""
        return (self.Instruction.mnemonic == 'PUSH' or
                self.Instruction.mnemonic == 'PUSHF')


    def is_uncnd_jmp(self):
        """判断是否为无条件跳转指令（流控制类型为 FC_UNC_BRANCH）。"""
        return self.Instruction.flowControl == 'FC_UNC_BRANCH'


    def is_sub_basepointer(self):
        """
        判断是否为 'sub ebp, xxx' 或 'sub rbp, xxx'。
        VM handler 中用此操作为 VM 栈分配空间（栈顶下移）。
        """
        return (('SUB' in self.Instruction.mnemonic) and
                (self.Instruction.instructionClass == 'ISC_INTEGER') and
                (self.Instruction.operands[0].name == 'EBP' or
                 self.Instruction.operands[0].name == 'RBP'))


    def is_add_basepointer(self):
        """
        判断是否为 'add ebp, xxx' 或 'add rbp, xxx'。
        VM handler 中用此操作释放 VM 栈空间（栈顶上移）。
        """
        return (('ADD' in self.Instruction.mnemonic) and
                (self.Instruction.instructionClass == 'ISC_INTEGER') and
                (self.Instruction.operands[0].name == 'EBP' or
                 self.Instruction.operands[0].name == 'RBP'))


    def get_op_str(self, op):
        """
        获取指定操作数的字符串表示（小写），如 'eax'、'[ebp+4]'。

        :param op: 操作数编号，1-based
        :return: 操作数字符串，越界返回 None
        """
        if op < 1 or op > len(self.Instruction.operands):
            return None
        return str(self.Instruction.operands[op-1]).lower()


    def get_op_size(self, op):
        """
        获取指定操作数的位宽（单位：bit），如 32、16、8。

        :param op: 操作数编号，1-based
        :return: 操作数位宽 (int)，越界返回 None
        """
        if op < 1 or op > len(self.Instruction.operands):
            return None
        return self.Instruction.operands[op-1].size


    def get_reg_name(self, op):
        """
        获取指定操作数涉及的寄存器名称（小写）。

        - 若操作数为寄存器类型：直接返回寄存器名（如 'eax'）
        - 若操作数为内存类型：返回基址寄存器名（如 '[ebp+4]' 返回 'EBP'）
        - 其他情况返回 None

        :param op: 操作数编号，1-based
        :return: 寄存器名字符串或 None
        """
        if op < 1 or op > len(self.Instruction.operands):
            return None
        if self.op_is_reg(op):
            return self.Instruction.operands[op-1].name.lower()
        elif self.op_is_mem(op):
            #abfrage
            return distorm3.Registers[self.Instruction.operands[op-1].index]
        else:
            return None


    def get_op_value(self, op):
        """
        获取立即数操作数的值。

        :param op: 操作数编号，1-based
        :return: 立即数值 (int)，若非立即数类型则返回 None
        """
        if op < 1 or op > len(self.Instruction.operands):
            return None
        if self.op_is_imm(op):
            return self.Instruction.operands[op-1].value
        else:
            return None


    def get_op_disp(self, op):
        """
        获取内存操作数的位移量（displacement），如 [ebp+8] 中的 8。

        :param op: 操作数编号，1-based
        :return: 位移值 (int)，仅对内存/绝对地址类型有效，否则返回 None
        """
        if op < 1 or op > len(self.Instruction.operands):
            return None
        if self.op_is_mem_abs(op) or self.op_is_mem(op):
            return self.Instruction.operands[op-1].disp
        else:
            return None


    def get_op(self, op):
        """
        获取 distorm3 原始操作数对象，可访问 type/name/size/value/index/disp 等底层属性。

        :param op: 操作数编号，1-based
        :return: distorm3.Operand 对象，越界返回 None
        """
        if op < 1 or op > len(self.Instruction.operands):
            return None
        return self.Instruction.operands[op-1]


    def is_rip_rel(self):
        """
        判断是否为 RIP 相对寻址（仅 x64 模式）。
        RIP 相对寻址用于访问全局变量/常量，如 mov rax, [rip+0x1234]。
        """
        return 'FLAG_RIP_RELATIVE' in self.Instruction.flags

