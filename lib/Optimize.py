#!/usr/bin/env python
"""
伪指令优化模块 - 对静态反混淆产生的push/pop伪指令序列进行多轮优化

优化管线（optimize函数中的执行顺序）：
1. replace_scratch_variables: 将栈暂存区操作数(ST_xx)替换为临时变量(T_xx)
2. replace_push_ebp: 将push ebp与其关联的栈值整合为数组操作数
3. replace_pop_push: 匹配push-pop对，转换为直接赋值(T_x = T_y)
4. reduce_assignements: 传递赋值消减(T2=T1, T3=T2 → T3=T1)
5. convert_read_array: 将vread数组操作数简化为直接赋值
6. change_nor_to_not: 当vnor的两个操作数相同时转换为vnot
7. reduce_ret: 删除vret附近的冗余赋值
8. add_comments: 为疑似函数参数访问的指令添加AOS注释
9. count_left_push/pop: 计数剩余push/pop便于分析
10. delete_overwrote_st: 删除被后续覆盖的栈暂存区赋值

@author: Tobias
"""


import lib.PseudoInstruction as PI
from lib import StartVal as SV
from lib.Register import (get_reg_class, get_reg_by_size)


def remove_dropped(ps_lst):
    """
    从伪指令列表中剔除所有已设置 drop 标记的项，并返回新列表。

    各优化步骤通常只将无用指令标为 drop，本函数负责真正收缩列表并释放对象。
    优化管线中在多个步骤之间及末尾多次调用（如第1步后、第2步后等），
    不属于单独的“第 N 步”优化规则，而是贯穿管线的清理例程。

    @param ps_lst: 伪指令列表
    @return: 不含 drop 项的新列表
    """
    ret = []
    for item in ps_lst:
        if not item.drop:
            ret.append(item)
        else:
            del item
    return ret


def find_last_inst(pp_lst, start_pos, op):
    """
    从 start_pos 起向前（索引递减）查找最近一次“定义或使用”操作数 op 的指令位置。

    原理：沿 push/pop 表示向前扫描；若遇到 POP 且目的操作数为 op，或遇到赋值类指令
    且 op 出现在操作数列表中，则认定找到数据来源。用于跳转目标地址的数据流回溯。
    不在 optimize 十步管线内；由 rec_find_addr / 跳转分析链路调用。

    @param pp_lst: push/pop 形式的伪指令序列
    @param start_pos: 搜索起始下标（从此处向前）
    @param op: 要匹配的操作数
    @return: 找到的下标，未找到则 None
    """
    pos = start_pos
    while pos != 0:
        inst = pp_lst[pos]
        if inst.inst_type == PI.POP_T and inst.op_lst[0] == op:
            #print 'pop', op
            return pos
        if inst.inst_class == PI.ASSIGNEMENT_T and op in inst.op_lst:
            #print 'assignement', op
            return pos
        pos -= 1
    return None


def start_rec(pp_lst, jmp_pos):
    """
    对位于 jmp_pos 的跳转指令，启动递归数据流分析以定位“计算跳转目标”相关的指令位置。

    以跳转指令的第一个操作数为起点调用 rec_find_addr，再将得到的每个位置与
    该跳转指令的地址组成 (pos, jmp_inst.addr) 元组列表返回。
    不在 optimize 十步管线内；由 get_jmp_addresses 在静态反混淆流程中调用。

    @param pp_lst: push/pop 形式的伪指令序列
    @param jmp_pos: 跳转指令在列表中的下标
    @return: [(与目标相关的指令下标, 跳转指令地址), ...]
    """
    jmp_inst = pp_lst[jmp_pos]
    if jmp_inst.list_len == 0:
        print 'could not find jmp address'
        return []
    jmp_op = jmp_inst.op_lst[0]
    pos_lst = rec_find_addr(pp_lst, jmp_pos, jmp_op, 20)
    ret_lst = []
    for x in pos_lst:
        ret_lst.append((x, pp_lst[jmp_pos].addr))
    return ret_lst


def rec_find_addr(pp_lst, pos, op, max_rec_depth):
    """
    递归回溯数据流，收集用于计算当前跳转目标操作数 op 的指令下标集合。

    原理：若 op 已为立即数或与 ebp 同类的帧指针寄存器，则终止并返回当前 pos；
    否则用 find_last_inst 找上游定义。对 POP 则配对 last_rel_push 继续追 push 源；
    对二元/多元赋值则向右操作数递归（深度受 max_rec_depth 限制）。
    不在 optimize 十步管线内；为 get_jmp_addresses 的核心子过程。

    @param pp_lst: push/pop 形式的伪指令序列
    @param pos: 当前考察的指令下标
    @param op: 当前追踪的操作数
    @param max_rec_depth: 最大递归深度，防止无限回溯
    @return: 参与目标地址计算的指令下标列表
    """
    if max_rec_depth == 0:
        return []
    if(op.type == PI.IMMEDIATE_T or
       (op.type == PI.REGISTER_T and
        get_reg_class(op.register) == get_reg_class('ebp'))):
        return [pos]
    inst_pos = find_last_inst(pp_lst, pos - 1, op)
    if inst_pos == None or inst_pos == 0:
        return []
    curr_inst = pp_lst[inst_pos]
    if curr_inst.inst_type == PI.POP_T:
        push_pos = last_rel_push(pp_lst, inst_pos - 1)
        if push_pos == None:
            return []
        new_op = pp_lst[push_pos].op_lst[0]
        new_pos = push_pos
        return [] + rec_find_addr(pp_lst, new_pos, new_op, max_rec_depth-1)
    elif (curr_inst.inst_class == PI.ASSIGNEMENT_T and
            curr_inst.list_len == 2):
        new_op = pp_lst[inst_pos].op_lst[1]
        new_pos = inst_pos
        return [] + rec_find_addr(pp_lst, new_pos, new_op, max_rec_depth-1)
    elif (curr_inst.inst_class == PI.ASSIGNEMENT_T and
            curr_inst.list_len >= 2):
        new_pos = inst_pos
        ret_lst = []
        for new_op in curr_inst.op_lst[1:]:
            ret_lst += rec_find_addr(pp_lst, new_pos , new_op, max_rec_depth-1)
        return ret_lst
    else:
        return []


def get_jmp_addresses(pp_lst, code_eaddr):
    """
    枚举序列中所有跳转指令，并尽可能解析出其目标地址，同时给各 JMP 写注释。

    原理：对每个 JMP 调用 start_rec 得到候选位置；若对应操作为寄存器则向前收集
    连续立即数 PUSH 作为多目标；若为落在典型代码段的立即数则直接记为地址。
    code_eaddr 当前实现中未参与判定，保留为接口。不在 optimize 十步管线内；
    在静态反混淆主流程中先于 find_basic_blocks 调用。

    @param pp_lst: push/pop 形式的伪指令序列
    @param code_eaddr: 混淆代码区结束地址
    @return: [(跳转目标地址, 跳转指令地址), ...]
    """
    jp_lst = []
    for pos, inst in enumerate(pp_lst):
        if inst.inst_type == PI.JMP_T:
            jp_lst.append(pos)
    poss_adr_pos = []
    for jpos in jp_lst:
        poss_adr_pos += start_rec(pp_lst, jpos)
    if len(poss_adr_pos) == 0:
        print 'could not find addresses'
        return []
    addrs = []
    for pos, jaddr in poss_adr_pos:
        inst = pp_lst[pos]
        if inst.op_lst[0].type == PI.REGISTER_T:
            push_pos = pos - 1
            count = 0
            tmp_addrs = []
            while(pp_lst[push_pos].inst_type == PI.PUSH_T and # TODO this seems kind of unsave
                  pp_lst[push_pos].op_lst[0].type == PI.IMMEDIATE_T and
                  push_pos != 0):
                tmp_addrs.append((pp_lst[push_pos].op_lst[0].val, jaddr))
                count += 1
                push_pos -= 1
            if count < 2:
                tmp_addrs = []
            addrs += tmp_addrs
        elif inst.op_lst[0].type == PI.IMMEDIATE_T:
            value = inst.op_lst[0].val
            if value > 0x400000 and value < 0x600000: #TODO
                addrs.append((value, jaddr))
    for pos_jmp in jp_lst:
        jmp_inst = pp_lst[pos_jmp]
        comment = 'jumps to: '
        found_addr = False
        for (addr, jaddr) in addrs:
            if jaddr == jmp_inst.addr:
                comment += '{0:#x}, '.format(addr)
                found_addr = True
        if found_addr:
            comment = comment[:len(comment)-2]
        else:
            comment += 'not found'
        jmp_inst.comment = comment
    return addrs


def find_basic_blocks(pp_lst, start_addr, jmp_addrs):
    """
    用经典 leader 算法根据入口点划分基本块，返回各块 [起始地址, 结束地址) 区间。

    原理：首指令地址与每个 JMP/RET 之后的第一条指令地址、以及 jmp_addrs 中的
    跳转目标地址均作为 leader；排序去重后相邻 leader 构成一块。若无任何块则返回 None。
    不在 optimize 十步管线内；在静态反混淆中在 get_jmp_addresses 之后用于控制流结构化。

    @param pp_lst: push/pop 形式的伪指令序列
    @param start_addr: 函数（或代码区）起始地址
    @param jmp_addrs: get_jmp_addresses 得到的 (目标地址, 跳转指令地址) 列表
    @return: [(块起始, 块结束), ...] 或 None
    """
    leader_lst = []
    leader_lst.append(start_addr)
    for pos, inst in enumerate(pp_lst):
        if inst.inst_type == PI.JMP_T or inst.inst_type == PI.RET_T:
            if pos < len(pp_lst) - 1:
                leader_lst.append(pp_lst[pos+1].addr)
                #leader_lst.append(inst.addr + 1) # i think this is better
            else: # code end
                leader_lst.append(inst.addr + 1)
    for addr in jmp_addrs:
        leader_lst.append(addr[0])
    basic_blocks = []
    rel_addrs = sorted(list(set(leader_lst)))
    for pos, x, in enumerate(rel_addrs):
        if (pos < len(rel_addrs) - 1):
            end_addr = rel_addrs[pos+1]
            basic_blocks.append((x, end_addr))
    del leader_lst
    del rel_addrs
    #for x, y in basic_blocks:
    #    print 'BasicBlock From: {0:#x}'.format(x), ' To: {0:#x}'.format(y)
    if basic_blocks == []:
        return None
    return basic_blocks


# still not sure if this is right for evry possibility
def last_rel_push(ps_lst, pos):
    """
    在给定位置 pos（通常为某条 POP）之前，用栈深度计数匹配与之配对的最近一条 PUSH。

    原理：从 pos 向前遍历，POP 增加“待平衡”栈量（按 size），PUSH 减少；当计数回到 0
    时的 PUSH 即为与当前 POP 在栈语义上配对的那条。用于跳转回溯与 replace_push_ebp 的栈扫描。
    optimize 第2步（replace_push_ebp）及 rec_find_addr 会间接使用；非独立管线步骤。

    @param ps_lst: 伪指令列表
    @param pos: 参考位置（一般为 POP 的下标）
    @return: 配对 PUSH 的下标，无法配对则 None
    """
    counter = 0
    while pos >= 0:
        if(ps_lst[pos].inst_type == PI.POP_T):
            counter += ps_lst[pos].size
        elif(ps_lst[pos].inst_type == PI.PUSH_T):
            if counter == 0:
                #return ps_lst[pos]
                return pos
            else:
                counter -= ps_lst[pos].size
        pos -= 1
    else: #no break
        return None



#     optimize_functions      #


def optimize(pseudo_inst_lst, has_loc):
    """
    对反混淆得到的伪指令序列执行完整十步优化管线并返回最终列表。

    执行顺序与模块文档一致：①replace_scratch_variables → ②replace_push_ebp →
    ③replace_pop_push → ④reduce_assignements（中间穿插 remove_dropped）→
    ⑤convert_read_array → 再次 reduce_assignements → ⑥change_nor_to_not →
    ⑦reduce_ret → ⑧add_comments → ⑨count_left_push / count_left_pop →
    ⑩delete_overwrote_st，最后 remove_dropped。return_push_ebp、scan_for_arguments
    在代码中注释掉，默认不执行。

    @param pseudo_inst_lst: 伪指令列表（原地修改并可能被步骤替换为新列表）
    @param has_loc: 当前函数是否含局部变量（影响 replace_push_ebp 是否附加 RET_ADDR/ARGS）
    @return: 优化并剔除 drop 后的伪指令列表
    """
    replace_scratch_variables(pseudo_inst_lst)
    pseudo_inst_lst = replace_push_ebp(pseudo_inst_lst, has_loc)
    pseudo_inst_lst = remove_dropped(pseudo_inst_lst)
    pseudo_inst_lst = replace_pop_push(pseudo_inst_lst)
    pseudo_inst_lst = remove_dropped(pseudo_inst_lst)
    reduce_assignements(pseudo_inst_lst)
    pseudo_inst_lst = remove_dropped(pseudo_inst_lst)
    pseudo_inst_lst = convert_read_array(pseudo_inst_lst)
    reduce_assignements(pseudo_inst_lst)
    pseudo_inst_lst = remove_dropped(pseudo_inst_lst)
    pseudo_inst_lst = change_nor_to_not(pseudo_inst_lst)
    pseudo_inst_lst = remove_dropped(pseudo_inst_lst)
    #return_push_ebp(pseudo_inst_lst)
    pseudo_inst_lst = remove_dropped(pseudo_inst_lst)
    reduce_ret(pseudo_inst_lst)
    pseudo_inst_lst = remove_dropped(pseudo_inst_lst)
    #scan_for_arguments(pseudo_inst_lst)
    add_comments(pseudo_inst_lst)
    count_left_push(pseudo_inst_lst)
    count_left_pop(pseudo_inst_lst)
    delete_overwrote_st(pseudo_inst_lst)
    pseudo_inst_lst = remove_dropped(pseudo_inst_lst)
    ##TODO remove unused just for whole function
    ##remove_unused(pseudo_inst_lst)
    ##pseudo_inst_lst = remove_dropped(pseudo_inst_lst)
    return remove_dropped(pseudo_inst_lst)


#unitll now this seems to be te best possibility
#think about saving the offsets of edi in Variable_T
def replace_scratch_variables(ps_lst):
    """
    将栈暂存区操作数 ST_xx 与对应 PUSH 上的同名操作数统一替换为临时变量 T_xx（VARIABLE_T）。

    原理：对每个目标为 SVARIABLE 的 POP，向前扫描 PUSH，通过 replace_st_push 替换同名
    scratch，再把该 POP 左端改为新的 VariableOperand。优化管线第 1 步。

    @param ps_lst: 伪指令列表（原地修改）
    """
    for pos, item in enumerate(ps_lst):
        if item.list_len <= 0:
            continue
        if item.inst_type != PI.POP_T or item.op_lst[0].type != PI.SVARIABLE_T:
            continue
        st_operand = item.op_lst[0]
        var_operand = PI.VariableOperand(PI.VARIABLE_T, st_operand.size)
        if replace_st_push(ps_lst, pos, st_operand, var_operand):
            item.op_lst[0] = var_operand


def replace_st_push(ps_lst, pos, to_replace, replace):
    """
    从 pos 之后顺序扫描，把所有 PUSH 上等于 to_replace 的操作数改为 replace，直到遇到
    下一个左操作数仍为 to_replace 的 POP 为止。

    用于保证同一 scratch 在一次 pop 定义作用域内的 push 源一致。优化管线第 1 步中
    replace_scratch_variables 的辅助函数。

    @param ps_lst: 伪指令列表
    @param pos: 起始下标（通常为当前 POP 的位置）
    @param to_replace: 被替换的栈暂存操作数
    @param replace: 替换后的变量操作数
    @return: 是否至少发生一次 PUSH 替换
    """
    lst_len = len(ps_lst)
    is_replace = False
    counter = pos + 1
    while counter < lst_len:
        curr_inst = ps_lst[counter]
        if curr_inst.list_len <= 0:
            counter += 1
            continue
        if(curr_inst.inst_type == PI.POP_T and
           curr_inst.op_lst[0].name == to_replace.name):
            return is_replace
        if(curr_inst.inst_type == PI.PUSH_T and
           curr_inst.op_lst[0].name == to_replace.name):
            ps_lst[counter].op_lst[0] = replace
            is_replace = True
        counter += 1
    return is_replace


def search_last_inst(count, ps_lst, last_pos, instruction_flag):
    """
    在 [0, last_pos) 范围内，找出最近 count 条 inst_type 等于 instruction_flag
    且未 drop 的指令下标。

    原理：顺序扫描并用长度为 count 的循环缓冲区保留最后若干匹配位置；若匹配不足
    count 条则返回 None。供 replace_pop_push 定位配对 PUSH。优化管线第 3 步的辅助函数。

    @param count: 需要匹配的条数
    @param ps_lst: 伪指令列表
    @param last_pos: 扫描上界（不含）
    @param instruction_flag: 指令类型标志（如 PI.PUSH_T）
    @return: 长度为 count 的下标列表（顺序与实现相关），不足则 None
    """
    i = 0
    ret = []
    while i < count:
        ret.append(-1)
        i += 1
    actual_pos = 0
    for pos, item in enumerate(ps_lst):
        if(pos >= last_pos):
            break
        if(item.inst_type == instruction_flag and not item.drop):
            ret[actual_pos % count] = pos
            actual_pos += 1
    if (ret.count(-1) != 0):
        return None
    else:
        return ret


def size_to_str(size):
    """
    将操作数字节宽度映射为后缀字母，用于 push/pop 部分宽度拆分时的临时操作数命名。

    映射：1→b，2→w，4→d，8→q；其它返回空串。优化管线第 3 步（replace_pop_push）中使用。

    @param size: 字节大小
    @return: 单字符后缀或空字符串
    """
    lookup = {1:'b', 2:'w', 4:'d', 8:'q'}
    try:
        return lookup[size]
    except:
        return ''


def is_mov_ebp(ps_lst, start, end):
    """
    判断闭区间 [start, end] 内是否存在 MOV_EBP 类指令（栈帧/setup 语义断点）。

    若存在则禁止将区间内 PUSH-POP 安全合并为赋值，以免破坏帧指针相关约定。
    优化管线第 3 步（replace_pop_push）的守卫条件。

    @param ps_lst: 伪指令列表
    @param start: 起始下标
    @param end: 结束下标
    @return: 是否存在 mov ebp
    """
    currpos = start
    while currpos <= end:
        inst = ps_lst[currpos]
        if inst.inst_type == PI.MOV_EBP_T:
            return True
        else:
            currpos += 1
    return False


def is_undef_inst(ps_lst, start, end):
    """
    判断闭区间 [start, end] 内是否存在未定义（UNDEF）伪指令。

    中间若有未定义指令则 PUSH-POP 数据流不可靠，replace_pop_push 跳过合并。
    优化管线第 3 步的守卫条件。

    @param ps_lst: 伪指令列表
    @param start: 起始下标
    @param end: 结束下标
    @return: 是否存在未定义指令
    """
    currpos = start
    while currpos <= end:
        inst = ps_lst[currpos]
        if inst.inst_type == PI.UNDEF_T:
            return True
        else:
            currpos += 1
    return False


def replace_pop_push(ps_lst):
    """
    将可安全配对的 PUSH-POP 消除为直接赋值（目的操作数 = 源操作数），并处理宽度不一致情况。

    原理：对每个 POP 用 search_last_inst 找最近 PUSH；若无 mov_ebp/undef 阻隔且宽度匹配
    则双方 drop 并生成 ASSIGNEMENT；宽度不等时拆分为 _PART 后缀的多个赋值或多次 PUSH 合并。
    优化管线第 3 步。

    @param ps_lst: 伪指令列表
    @return: 新的伪指令列表（含新生成的赋值指令）
    """
    ret = []
    rest_size = None
    for pos, item in enumerate(ps_lst):
        if item.inst_type == PI.POP_T and not item.drop:
            pos_lst = search_last_inst(1, ps_lst, pos, PI.PUSH_T)
            if pos_lst == None:
                ret.append(item)
                continue
            push_pos = pos_lst[0]
            #the reduction of push and pop must not take place
            #if there is a change of the stackpointer or a
            #undefined instruction between the push and pop instruction
            if (is_mov_ebp(ps_lst, push_pos, pos) or
                is_undef_inst(ps_lst, push_pos, pos)):
                ret.append(item)
                continue
            push_inst = ps_lst[push_pos]
            if item.size == push_inst.size:
                item.drop = True
                push_inst.drop = True
                op = ps_lst[push_pos].op_lst[0]
                assign_op = item.op_lst[0]
                ret.append(
                    PI.PseudoInstruction('', item.addr, [assign_op, op], -1,
                                        PI.NOTHING_T, PI.ASSIGNEMENT_T)
                    )
            # popsize lower push size
            elif item.size < push_inst.size:
                #dont know if this is bad style but it works
                if rest_size == None:
                    counter = 0
                    rest_size = push_inst.size
                rest_size = rest_size - item.size
                push_op = ps_lst[push_pos].op_lst[0]
                suffix = '_PART' + str(counter) + '_' + size_to_str(item.size)
                op = PI.PseudoOperand(push_op.type,
                                      push_op.name + suffix, push_op.size)
                assign_op = item.op_lst[0]
                ret.append(
                    PI.PseudoInstruction('', item.addr, [assign_op, op],
                                         -1, PI.NOTHING_T, PI.ASSIGNEMENT_T)
                    )
                counter += 1
                item.drop = True
                if rest_size == 0:
                    rest_size = None
                    push_inst.drop = True
            # popsize greater push size
            elif item.size > push_inst.size:
                needed_pushes = item.size / push_inst.size
                pos_lst = search_last_inst(needed_pushes, ps_lst, pos, PI.PUSH_T)
                if pos_lst == None:
                    continue
                for i, p_pos in enumerate(reversed(sorted(pos_lst))):
                    #op = ps_lst[push_pos].op_lst[0]
                    push_op = ps_lst[p_pos].op_lst[0]
                    suffix = '_PART' + str(i) + '_' + size_to_str(push_inst.size)
                    assign_op = PI.PseudoOperand('', item.op_lst[0].name + suffix, item.op_lst[0].size,)
                    ret.append(
                        PI.PseudoInstruction('', item.addr, [assign_op, push_op],
                                             -1, PI.NOTHING_T, PI.ASSIGNEMENT_T)
                        )
                    ps_lst[p_pos].drop = True
                item.drop = True
            else:
                ret.append(item)
        else:
            ret.append(item)
    return ret

# TODO verbessern
def replace_temporals(ps_lst, pos, to_replace, replace):
    """
    从 pos+1 起向后传播替换：将所有引用 to_replace 的地方改为 replace，直至遇到对
    to_replace 的重新定义（赋值左值）等终止条件。

    会深入 ARRAY 内元素；POINTER 类型单独构造新操作数。若首遇“对 to_replace 的赋值”
    且为 NOTHING 赋值类则返回 False 以避免错误删除。优化管线第 4 步 reduce_assignements
    的辅助函数。

    @param ps_lst: 伪指令列表
    @param pos: 当前赋值指令位置（从此之后开始替换）
    @param to_replace: 被消去的临时操作数
    @param replace: 替换为的操作数
    @return: 是否发生了替换
    """
    lst_len = len(ps_lst)
    counter = pos + 1
    found = False
    while counter < lst_len:
        for op_pos, op in enumerate(ps_lst[counter].op_lst):
            if op.type == PI.ARRAY_T:
                for a_pos, a_op in enumerate(op.op_val):
                    if a_op.name == to_replace.name:
                        ps_lst[counter].op_lst[op_pos].op_val[a_pos] = replace
                        found = True
            if op.name == to_replace.name: # maybe improve this comparion
                #idee: falls der Variablen etwas neues zugewiesen
                #wird bevor(op_pos == 0) beende das ersetzen
                #die letze instruction kann geloescht werden
                if(op_pos == 0 and ps_lst[counter].inst_class == PI.ASSIGNEMENT_T and
                   ps_lst[counter].inst_type == PI.NOTHING_T): # TODO improve
                    return False # return True
                if(op.type == PI.POINTER_T):
                    ps_lst[counter].op_lst[op_pos] = PI.PseudoOperand(
                            PI.POINTER_T, replace.name,
                            replace.size, counter)
                else:
                    ps_lst[counter].op_lst[op_pos] = replace
                found = True
        counter += 1
    return found
        


def reduce_assignements(ps_lst):
    """
    对形如 T_a = T_b 的简单赋值链做传递闭包式消减，例如 T2=T1 与 T3=T2 合并为对 T3=T1 的等价使用。

    原理：遍历 NOTHING 类的 VARIABLE 左值赋值，调用 replace_temporals 把后续对左值的
    引用替换为右值；成功则标记当前赋值为 drop。在管线中第 5 步前后各执行一次以配合
    convert_read_array。优化管线第 4 步（并在第 5 步后再跑一次）。

    @param ps_lst: 伪指令列表（原地修改）
    """
    for pos, item in enumerate(ps_lst):
        if (item.inst_class == PI.ASSIGNEMENT_T
            and item.inst_type == PI.NOTHING_T
            and (item.op_lst[0].type == PI.VARIABLE_T)):
                 #item.op_lst[0].type == PI.SVARIABLE_T)):
            if replace_temporals(ps_lst, pos, item.op_lst[0], item.op_lst[1]):
                item.drop = True
            else:
                item.drop = False
            


def find_further_result_op(ps_lst, start_pos, end_pos, op):
    """
    从 start_pos 起向右连续扫描赋值指令，收集所有左值等于 op 的赋值下标。

    遇到非赋值类指令即停止。供 reduce_ret 识别 vret 前对同一“结果操作数”的多次赋值。
    优化管线第 7 步（reduce_ret）的辅助函数。

    @param ps_lst: 伪指令列表
    @param start_pos: 起始下标
    @param end_pos: 结束下标
    @param op: 要匹配左值的操作数
    @return: 赋值位置下标列表
    """
    positions = []
    pos = start_pos
    while pos <= end_pos:
        if ps_lst[pos].inst_class != PI.ASSIGNEMENT_T:
            break
        if ps_lst[pos].op_lst[0].name == op.name:
            positions.append(pos)
        pos += 1
    return positions


# need further testing
def reduce_ret(ps_lst):
    """
    在 RET 指令地址处开始，将紧挨在返回前的连续赋值中冗余的“弹栈式”赋值标为 drop。

    原理：对同一左值的多次赋值仅保留最后一次，之前的标记删除；左值与右值同名
    的无意义赋值亦删除。优化管线第 7 步。

    @param ps_lst: 伪指令列表（原地修改 drop）
    """
    for item in ps_lst:
        if(item.inst_type == PI.RET_T):
            break
    else: # no break
        return
    ret_addr = item.addr
    #find first item with addr
    for pos, inst in enumerate(ps_lst):
        if(inst.addr == ret_addr):
            break
    else: #no break
        return
    while pos < len(ps_lst):
        inst = ps_lst[pos]
        if inst.inst_class != PI.ASSIGNEMENT_T:
            break
        result_op = inst.op_lst[0]
        pos_lst = find_further_result_op(ps_lst,
                                    pos, len(ps_lst)-1, result_op)
        #drop all instead of the last one
        #these assignements are 'pops'
        for inst_pos in pos_lst[:len(pos_lst)-1]:
            ps_lst[inst_pos].drop = True
        #drop assignements where both ops are the same
        if result_op.name == inst.op_lst[1].name:
            ps_lst[pos].drop = True
        pos += 1



def replace_push_ebp(ps_lst, has_loc):
    """
    将 push ebp/rbp 与其栈上关联的一组 push 值聚合为单个 ARRAY 操作数，便于后续按数组下标理解栈帧。

    原理：用 scan_stack 收集两枚 ebp push 之间的 push 序列，按是否含 ret、是否 mov_ebp、
    has_loc 决定是否追加 RET_ADDR、ARGS 占位表达式。优化管线第 2 步。

    @param ps_lst: 伪指令列表
    @param has_loc: 是否存在局部变量
    @return: 替换后的新伪指令列表
    """
    ret = []
    is_ret = False
    for r_item in ps_lst:
        if r_item.inst_type == PI.RET_T:
            is_ret = True
    for pos, item in enumerate(ps_lst):
        if(item.inst_type == PI.PUSH_T and
           item.op_lst[0].type == PI.REGISTER_T and
           get_reg_class(item.op_lst[0].register) == get_reg_class('ebp')):
            push_pos = last_rel_push(ps_lst, pos-1)
            if push_pos == None:
                ret.append(item)
            else:
                push_inst = ps_lst[push_pos]
                if(push_inst.list_len == 0 or
                   push_inst.addr == item.addr):#need this for saving push ebp 
                    ret.append(item)
                    continue
                push_inst_op = ps_lst[push_pos].op_lst[0]
                push_poss = scan_stack(ps_lst, pos)
                val_arr = []
                #all pos should be push so dont need a test here
                for pos in push_poss:
                    val_arr.append(ps_lst[pos].op_lst[0])
                #TODO look for better possibility
                if is_ret:
                    if (((is_mov_ebp(ps_lst, 0, pos)) and
                        is_mov_ebp(ps_lst, 0, len(ps_lst)-1)) or
                        not has_loc):
                        val_arr.append(PI.PseudoOperand(PI.EXP_T, 'RET_ADDR', 0))
                        val_arr.append(PI.PseudoOperand(PI.EXP_T, 'ARGS', 0))
                else:
                    if (((not is_mov_ebp(ps_lst, 0, pos)) and
                        is_mov_ebp(ps_lst, 0, len(ps_lst)-1)) or
                        not has_loc):
                        val_arr.append(PI.PseudoOperand(PI.EXP_T, 'RET_ADDR', 0))
                        val_arr.append(PI.PseudoOperand(PI.EXP_T, 'ARGS', 0))
                new_op = PI.ArrayOperand(
                            PI.ARRAY_T, ps_lst[push_poss[0]].size,
                            len(val_arr), val_arr)
                new_inst = PI.PseudoInstruction(
                    item.mnem, item.addr,
                    [new_op], item.size,
                    item.inst_type, item.inst_class)
                #new_inst.comment = comment
                ret.append(new_inst)
        else:
            ret.append(item)
    return ret


#just do this after reduction
def return_push_ebp(ps_lst):
    """
    将仍为 PUSH 且操作数为 ARRAY 的指令还原为普通的 push ebp/rbp（按当前反汇编位宽选寄存器）。

    适用于在 replace_push_ebp 与赋值消减之后再恢复更接近原始汇编的形态。
    当前 optimize 中该调用被注释掉，未接入十步管线；若启用应放在聚合与消减之后。

    @param ps_lst: 伪指令列表（原地修改）
    """
    for inst in ps_lst:
        if (inst.inst_type == PI.PUSH_T and
            inst.op_lst[0].type == PI.ARRAY_T):
            reg_class = get_reg_class('ebp')
            register = get_reg_by_size(reg_class, SV.dissassm_type)
            ebp_op = PI.PseudoOperand(PI.REGISTER_T, register,
                                      SV.dissassm_type, register)
            inst.op_lst[0] = ebp_op


# get pushes that are on stack between two push ebp
def scan_stack(ps_lst, s_pos):
    """
    在给定 push ebp/rbp 位置 s_pos，自外向内列出“当前栈上”对应的各 PUSH 指令下标。

    原理：反复 last_rel_push 向前找配对 push，直到区间内出现 mov_ebp 为止并从列表移除
    该位置。优化管线第 2 步中 replace_push_ebp 使用。

    @param ps_lst: 伪指令列表
    @param s_pos: 当前 push ebp 的下标
    @return: 从栈顶到帧方向相关的 push 下标列表
    """
    a = last_rel_push(ps_lst, s_pos-1)
    pos_lst = []
    while a != None:
        pos_lst.append(a)
        #if (#ps_lst[a].inst_type == PI.PUSH_T and
            #((ps_lst[a].op_lst[0].type == PI.REGISTER_T and
            #  get_reg_class(ps_lst[a].op_lst[0].register) == get_reg_class('ebp')) or
            #  ps_lst[a].op_lst[0].type == PI.ARRAY_T) or
            #is_mov_ebp(ps_lst, a, s_pos)):
        if is_mov_ebp(ps_lst, a, s_pos):
            pos_lst.remove(a)
            break
        a = last_rel_push(ps_lst, a-1)
    return pos_lst


def convert_read_array(ps_lst):
    """
    将右端为数组操作数的 READ 类赋值（vread）简化为普通赋值：左值 = 数组的第一个元素。

    仅处理 list_len==2、ASSIGNEMENT 且 inst_type 为 READ、右操作数为 ARRAY 的情况。
    优化管线第 5 步。

    @param ps_lst: 伪指令列表
    @return: 转换后的新列表
    """
    ret = []
    for inst in ps_lst:
        if inst.list_len != 2:
            ret.append(inst)
            continue
        if (inst.inst_class == PI.ASSIGNEMENT_T and
            inst.inst_type == PI.READ_T):
            right_op = inst.op_lst[1]
            if right_op.type != PI.ARRAY_T:
                ret.append(inst)
                continue
            left_op = inst.op_lst[0]
            new_right_op = right_op.op_val[0]
            new_inst = PI.PseudoInstruction('', inst.addr,
                [left_op, new_right_op], -1, #inst.size instead of -1 may be better
                PI.NOTHING_T, PI.ASSIGNEMENT_T)
            ret.append(new_inst)
        else:
            ret.append(inst)
    return ret


def change_nor_to_not(ps_lst):
    """
    当 vnor 的两个源操作数相同（a NOR a）时，改写为语义等价的 vnot 单操作赋值。

    利用恒等式 NOR(x,x) = NOT(x)。优化管线第 6 步。

    @param ps_lst: 伪指令列表
    @return: 替换后的新列表
    """
    ret = []
    for inst in ps_lst:
        if inst.list_len < 3:
            ret.append(inst)
            continue
        if (inst.inst_class == PI.ASSIGNEMENT_T and
            inst.inst_type == PI.NOR_T):
            nor_op1 = inst.op_lst[1]
            nor_op2 = inst.op_lst[2]
            if nor_op1 == nor_op2:
                left_op = inst.op_lst[0]
                new_inst = PI.PseudoInstruction('vnot', inst.addr, [left_op, nor_op1], inst.size, PI.NOT_T, PI.ASSIGNEMENT_T)
                ret.append(new_inst)
            else:
                ret.append(inst)
        else:
            ret.append(inst)
    return ret


# Assumption: an add to an array pointer,
# which leaves the known stack could point
# to an argument
def scan_for_arguments(ps_lst):
    """
    扫描“数组指针 + 立即数偏移”的 ADD 赋值，若偏移超过数组元素覆盖范围则注释提示可能访问参数。

    假设：对数组指针做加法且位移出已知栈数组可能指向调用参数区。optimize 中该步骤
    被注释掉，未接入十步管线；逻辑与 add_comments 部分相似但判定更宽。

    @param ps_lst: 伪指令列表（原地写 comment）
    """
    for inst in ps_lst:
        if (inst.inst_type == PI.ADD_T and
            inst.inst_class == PI.ASSIGNEMENT_T):
            array_pos = None
            imm_pos = None
            for pos, op in enumerate(inst.op_lst):
                if op.type == PI.ARRAY_T:
                    array_pos = pos
                if op.type == PI.IMMEDIATE_T:
                    imm_pos = pos
            if array_pos == None or imm_pos == None:
                continue
            imm_val = inst.op_lst[imm_pos].val
            array_op = inst.op_lst[array_pos]
            if imm_val > array_op.size * array_op.len:
                inst.comment = 'AOS: Could be Argument'


def add_comments(ps_lst):
    """
    为疑似通过数组基址访问函数参数（或前驱基本块/局部）的 ADD 指令添加 AOS 风格注释。

    原理：识别 ASSIGNEMENT + ADD 且同时含 ARRAY 与立即数；根据数组是否含 EXP 扩展项
    调整有效长度，与 imm 比较后设置不同提示文案。优化管线第 8 步。

    @param ps_lst: 伪指令列表（原地写 comment）
    """
    for inst in ps_lst:
        if (inst.inst_type == PI.ADD_T and
            inst.inst_class == PI.ASSIGNEMENT_T):
            array_pos = None
            imm_pos = None
            for pos, op in enumerate(inst.op_lst):
                if op.type == PI.ARRAY_T:
                    array_pos = pos
                if op.type == PI.IMMEDIATE_T:
                    imm_pos = pos
            if array_pos == None or imm_pos == None:
                continue
            imm_val = inst.op_lst[imm_pos].val
            array_op = inst.op_lst[array_pos]
            has_ext = False
            for val in array_op.op_val:
                if val.type == PI.EXP_T:
                    has_ext = True
            op_len = array_op.len
            if has_ext:
                op_len -= 2
            if imm_val >= array_op.size * op_len:
                inst.comment = 'AOS: Could be Argument'
                if has_ext:
                    inst.comment += '(positive value)'
                else:
                    inst.comment += ('(push from prev BB or local variable)')

def count_left_push(ps_lst):
    """
    从序列末尾向前遍历，统计每个 PUSH 之后（到下一个 mov_ebp 重置前）“右侧还剩多少 push”，
    把计数写入该指令的 comment 字段便于人工对照栈形。

    优化管线第 9 步（与 count_left_pop 成对，用于分析而非删除指令）。

    @param ps_lst: 伪指令列表（原地修改 comment）
    """
    count = 0
    for inst in reversed(ps_lst):
        if inst.inst_type == PI.MOV_EBP_T:
            count = 0
        if inst.inst_type == PI.PUSH_T:
            inst.comment = str(count)
            count += 1


def count_left_pop(ps_lst):
    """
    从前向后扫描，统计每个 POP 之前（自上一个 mov_ebp 起）已出现的 POP 数量，
    写入 comment 作为序号标记，便于与 push 侧计数对照。

    优化管线第 9 步。

    @param ps_lst: 伪指令列表（原地修改 comment）
    """
    count = 0
    for inst in ps_lst:
        if inst.inst_type == PI.MOV_EBP_T:
            count = 0
        if inst.inst_type == PI.POP_T:
            inst.comment = str(count)
            count += 1

def delete_overwrote_st(ps_lst):
    """
    对同一 ST（SVARIABLE）左值的多次赋值，仅保留最后一次有效定义，将其余赋值标为 drop。

    原理：先扫一遍建立每个 scratch 编号到“最后赋值位置”的映射，再第二遍把早于该位置
    的同左值赋值标记删除。优化管线第 10 步。

    @param ps_lst: 伪指令列表（原地修改 drop）
    """
    op_pos_dict = {}
    # search for last Assignement to st variable
    for pos, inst in enumerate(ps_lst):
        if (inst.inst_class == PI.ASSIGNEMENT_T and
            inst.inst_type == PI.NOTHING_T and
            inst.op_lst[0].type == PI.SVARIABLE_T):
            op_pos_dict[inst.op_lst[0].number] = pos
    # delete all Assignements to st variable instead of the last
    for pos, inst in enumerate(ps_lst):
        if (inst.inst_class == PI.ASSIGNEMENT_T and
            inst.inst_type == PI.NOTHING_T and
            inst.op_lst[0].type == PI.SVARIABLE_T):
            left_op = inst.op_lst[0]
            if pos < op_pos_dict[left_op.number]:
                inst.drop = True


########################
# not used at mom but think about
########################
#def further_used(ps_lst, op, start_pos):
#    pos = start_pos
#    last_pos = len(ps_lst) - 1
#    while pos <= last_pos:
#        if (ps_lst[pos].drop):
#            #print 'hallo'
#            pos += 1
#            continue
#        for op_pos, r_op in enumerate(ps_lst[pos].op_lst):
#            if r_op.name == op.name:
#                return True
#        pos += 1
#    return False


#def remove_unused(ps_lst):
#    change = True
#    while change:
#        change = False
#        for pos, item in enumerate(ps_lst):
#            if item.list_len == 0:
#                continue
#            if not further_used(ps_lst, item.op_lst[0], pos + 1):
#                if item.op_lst[0].type == PI.REGISTER_T:
#                    continue
#                if not item.drop:
#                    item.drop = True
#                    change = True
#        print change
