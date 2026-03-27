# coding=utf-8
"""
动态分析调度模块 - 封装所有动态分析功能的入口函数

主要功能：
1. Trace管理：生成(gen_instruction_trace)、加载(load_trace)、保存(save_trace)
2. 评分系统(grading_automaton)：综合多种分析结果自动评分
3. 聚类分析(clustering_analysis)：将trace按重复模式分组
4. 输入/输出分析(input_output_analysis)：黑盒追踪VM函数I/O
5. 优化分析(optimization_analysis)：交互式trace优化
6. DynamicAnalyzer：多线程分析封装类

所有分析函数在操作trace前都先deepcopy，保护全局原始数据。
"""

__author__ = 'Anatoli Kalysch'

from threading import Thread

from ui.UIManager import GradingViewer
from ui.UIManager import OptimizationViewer
from ui.UIManager import StackChangeViewer
from ui.UIManager import VMInputOuputViewer

from DebuggerHandler import load, save, get_dh
from lib.TraceAnalysis import *
from lib.VMRepresentation import get_vmr
from ui.NotifyProgress import NotifyProgress
from ui.UIManager import ClusterViewer
from bp import *

### DEBUGGER LOADING STRATEGIES ###
# IDA Debugger
def load_idadbg(self):
    """实例化 IDA 内置调试器后端。作为 `available_debuggers` 中的可选项，供 `load_dbg` 按用户选择加载。"""
    from IDADebugger import IDADebugger
    return IDADebugger()

# OllyDbg
def load_olly(self):
    """实例化 OllyDbg 调试器适配器。作为 `available_debuggers` 中的可选项，供 `load_dbg` 按用户选择加载。"""
    from OllyDebugger import OllyDebugger
    return OllyDebugger()

# Bochs Dbg
def load_bochsdbg(self):
    """切换到 Bochs 调试引擎并返回 IDA 调试器封装。作为 `available_debuggers` 中的可选项，供 `load_dbg` 按用户选择加载。"""
    from IDADebugger import IDADebugger
    LoadDebugger('Bochs', 0)
    return IDADebugger()

# Win32 Dbg
def load_win32dbg(self):
    """切换到 Win32 调试引擎并返回 IDA 调试器封装。作为 `available_debuggers` 中的可选项，供 `load_dbg` 按用户选择加载。"""
    from IDADebugger import IDADebugger
    LoadDebugger('win32', 0)
    return IDADebugger()

# Immunity Dbg
def load_immunitydbg(self):
    """返回基于 IDA 的调试器封装（Immunity 场景）。作为 `available_debuggers` 中的可选项，供 `load_dbg` 按用户选择加载。"""
    from IDADebugger import IDADebugger
    return IDADebugger()


# Working with Win32Dbg, BochsDbg, OllyDbg
available_debuggers = [load_idadbg, load_olly, load_bochsdbg, load_win32dbg, load_immunitydbg]


### INIT AND LOAD CONTEXT ###

def prepare_trace():
    """
    从全局 VM 表示中取当前指令 trace，若尚未加载则从磁盘读取；返回其深拷贝。

    在各分析/评分/可视化入口中作为第一步调用，避免直接修改 `vmr.trace` 污染全局状态。
    """
    vmr = get_vmr()
    if vmr.trace is None:
        vmr.trace = load()  # 全局尚无 trace 时从磁盘载入
    return deepcopy(vmr.trace)  # 返回副本，避免分析过程破坏 vmr 中的原始列表

def prepare_vm_ctx():
    """
    返回当前 VM 上下文结构的深拷贝，供只读或局部修改使用。

    在需要 VM 布局信息但不允许写回全局 `vmr.vm_ctx` 的流程中使用，与 `prepare_trace` 同属数据隔离层。
    """
    vmr = get_vmr()
    return deepcopy(vmr.vm_ctx)  # 避免分析逻辑意外修改已提交的 vm_ctx

def prepare_vm_operands():
    """
    返回当前 VM 操作数相关状态的深拷贝。

    在操作数级分析中避免就地改写全局 `vmr.vm_operands`，保证多次分析结果可复现。
    """
    vmr = get_vmr()
    return deepcopy(vmr.vm_operands)  # 与 prepare_trace 同理，隔离全局 VM 操作数缓存

def load_dbg(choice):
    """
    根据用户在 `available_debuggers` 中的索引构造调试器句柄并校验可用性。

    在生成指令 trace（`gen_instruction_trace`）等需要真实调试会话的步骤之前建立调试后端。
    """
    dbg_handl = get_dh(available_debuggers[choice])  # choice 与菜单中调试器列表下标一致
    if dbg_handl.check:
        return dbg_handl
    else:
        raise Exception("[*] Could not load debugger! Please check if the selected debugger is available.")

def load_trace():
    """
    从持久化存储读取 trace 并写回全局 `vmr.trace`。

    在 UI 或脚本选择“加载已有 trace”时调用，为后续各项动态分析提供数据源。
    """
    vmr = get_vmr()
    trace = load()
    vmr.trace = trace  # 替换内存中的活动 trace

def save_trace():
    """
    将当前内存中的 trace（经 `prepare_trace` 深拷贝后）保存到磁盘。

    在分析会话结束或用户显式保存时调用，与 `load_trace` 成对使用。
    """
    trace = prepare_trace()
    save(trace)  # 将副本序列化到 DebuggerHandler 配置的存储路径

def gen_instruction_trace(choice):
    """
    使用指定调试器后端采集指令级 trace，并写入全局 `vmr.trace`。

    动态流水线的数据源头：必须先有 trace，后续的地址启发式、聚类、评分等才有输入。
    """
    bp()
    dbg_handl = get_dh(choice)  # DebuggerHandler 持有的具体调试器实例（由 UI 传入已选后端）
    vmr = get_vmr()
    trace = dbg_handl.gen_instruction_trace()  # 驱动调试会话单步/运行并收集 Traceline 列表
    if trace is not None:
        vmr.trace = trace
    else:
        raise Exception('[*] Trace seems to be None, so it was disregarded!')

### ANALYSIS FUNCTIONALITY###
# TODO multithreading !!!
class DynamicAnalyzer(Thread):
    """
    在独立线程中执行单次 trace 分析函数，并用深拷贝隔离输入数据。

    用于 `input_output_analysis` 等需并行跑多个耗时分析（如虚拟寄存器、输入、输出）时，缩短总等待时间且不共享可变 trace。
    """
    def __init__(self, func, trace, **kwargs):
        """绑定分析函数 `func`、trace 副本及关键字参数，结果初始为 None。"""
        super(DynamicAnalyzer, self).__init__()
        self.analysis = func
        self.trace = deepcopy(trace)
        self.kwargs = kwargs
        self.result = None

    def run(self):
        """线程入口：对副本 trace 调用 `self.analysis`，返回值存入 `self.result`。"""
        self.result = self.analysis(self.trace, self.kwargs)

    def get_result(self):
        """在 `join()` 之后调用，取回子线程中完成的分析结果。"""
        return self.result


def address_heuristic():
    """
    统计 trace 中每条指令地址的出现次数并在输出窗口打印摘要。

    作为轻量级探索步骤，帮助人工判断热点地址与罕见地址，常与后续 `init_grading` 的“稀有地址高分”思路对照。
    """
    w = NotifyProgress('Address count')
    w.show()
    try:
        trace = prepare_trace()
        w.pbar_update(40)
        ac = address_count(deepcopy(trace))  # 再次深拷贝，避免 address_count 内部改动影响后续使用的 trace
        w.pbar_update(60)
        w.close()

        for addr, count in ac:
            print 'Address %x (Disasm: %s) was encountered %s times.' % (addr, GetDisasm(addr), count)
    except:
        print '[*] An exception occurred! Quitting! '
        w.close()

# analysis functions supporting manual flag
manual_func = [find_output, find_input, find_virtual_regs, follow_virt_reg]
def manual_analysis(choice):
    """
    根据索引从 `manual_func` 中选一项，以 `manual=True` 交互模式在 trace 上运行。

    供高级用户逐项触发 find_output/find_input 等函数，输出主要在 IDA 输出窗口，部分流程会弹窗询问。
    """
    w = NotifyProgress('Address count')  # 与 address_heuristic 共用标题，表示耗时分析进度
    w.show()
    trace = prepare_trace()
    func = manual_func[choice]  # find_output / find_input / find_virtual_regs / follow_virt_reg 之一
    w.pbar_update(10)
    func(deepcopy(trace), manual=True, update=w)
    w.close()

def input_output_analysis(manual=False):
    """
    黑盒分析 VM 函数的输入/输出相关 trace 片段，并在界面中对比展示。

    在自动模式下用多线程并行完成虚拟寄存器、输入、输出推断；手动模式则先让用户选定函数再跑输入/输出链，是理解 VM 数据流的关键环节。
    """
    func_addr = None
    if manual:
        func_addr = ChooseFunction('Please select the function for black box analysis')
    w = NotifyProgress('In/Out')
    w.show()

    trace = prepare_trace()
    vmr = get_vmr()
    # 为每个相关虚拟寄存器准备 follow 得到的 trace 片段，供查看器展示
    ctx = {}
    try:
        if func_addr is not None:  # TODO enable input / output analysis of all functions
            # 手动模式：仅同步求输入/输出集合并关闭进度条（当前未弹出 VMInputOuputViewer）
            input = find_input(deepcopy(trace))
            output = find_output(deepcopy(trace))
            w.close()
        else:
            # 三路并行：虚拟寄存器、输入、输出推断，缩短 wall-clock 时间
            vr = DynamicAnalyzer(find_virtual_regs, trace)
            w.pbar_update(10)
            vr.start()
            input = DynamicAnalyzer(find_input, trace)
            w.pbar_update(10)
            input.start()
            output = DynamicAnalyzer(find_output, trace)
            w.pbar_update(10)
            output.start()
            vr.join()
            w.pbar_update(20)
            vr = vr.get_result()
            # 对每个识别到的虚拟寄存器生成沿 trace 的摘录，映射到真实寄存器名
            for key in vr.keys():
                if get_reg_class(key) is not None:
                    ctx[key] = follow_virt_reg(deepcopy(trace), virt_reg_addr=vr[key], real_reg_name=key)
            vmr.vm_stack_reg_mapping = ctx
            w.pbar_update(20)
            input.join()
            w.pbar_update(10)
            output.join()
            w.pbar_update(10)

            w.close()
            v = VMInputOuputViewer(input.get_result(), output.get_result(), ctx)
            v.Show()
    except:
        w.close()

def clustering_analysis(visualization=0, grade=False, trace=None):
    """
    对 trace 做重复模式聚类，并可选地在 ClusterViewer / StackChangeViewer 中可视化。

    揭示 VM 解释循环中的重复指令块，为人工切片和 `grading_automaton` 中“非重复行加分”提供结构依据；也可传入已有 trace 避免重复读取全局状态。
    """
    if trace is None:
        trace = prepare_trace()

    w = NotifyProgress('Clustering')
    w.show()

    try:
        try:
            # 聚类前先尽量常量传播与栈地址传播，使重复模式更稳定
            if not trace.constant_propagation:
                trace = optimization_const_propagation(trace)
            if not trace.stack_addr_propagation:
                trace = optimization_stack_addr_propagation(trace)
        except:
            pass
        w.pbar_update(30)
        vr = find_virtual_regs(deepcopy(trace))
        w.pbar_update(20)
        cluster = repetition_clustering(deepcopy(trace))
        w.pbar_update(25)
        if visualization == 0:

            v0 = ClusterViewer(cluster, create_bb_diff, trace.ctx_reg_size, save_func=save)  # 图形化聚类结果
            w.pbar_update(24)
            v0.Show()

            prev_ctx = defaultdict(lambda: 0)
            stack_changes = defaultdict(lambda: 0)
            for line in cluster:
                if isinstance(line, Traceline):
                    prev_ctx = line.ctx
                else:
                    stack_changes = create_cluster_gist(line, trace.ctx_reg_size, prev_ctx, stack_changes)
                    prev_ctx = line[-1].ctx
            # 按地址排序栈变化摘要，便于在 StackChangeViewer 中浏览
            sorted_result = sorted(stack_changes.keys())
            sorted_result.reverse()
            w.close()
            v1 = StackChangeViewer(vr, sorted_result, stack_changes)
            v1.Show()
        else:
            w.close()
            visualize_cli(cluster)
    except:
        w.close()

def optimization_analysis():
    """
    打开 OptimizationViewer，让用户交互式裁剪、标记或保存优化后的 trace。

    位于“原始 trace → 各类自动分析”之间的手工精修环节，常与保存后的 trace 再喂给聚类或评分。
    """
    trace = prepare_trace()
    v = OptimizationViewer(trace, save=save)  # 传入可写 trace 与保存回调，便于用户确认后落盘
    v.Show()

def dynamic_vmctx(manual=False):
    """
    根据当前 trace 推断 VM 代码区间、基址等上下文并写回 `vmr.vm_ctx`。

    为静态/动态后续阶段提供统一的 VM 映像描述；`manual=True` 时在输出窗口打印关键地址便于核对。
    """
    trace = prepare_trace()
    vm_ctx = dynamic_vm_values(trace)  # 根据实际执行到的指令推断 VM 映像边界与指针寄存器角色
    vmr = get_vmr()
    vmr.vm_ctx = vm_ctx  # 写回全局，供静态阶段与 UI 共享同一份上下文
    if manual:
        print 'Code Start: %x; Code End: %x; Base Addr: %x; VM Addr: %x' % (vm_ctx.code_start, vm_ctx.code_end, vm_ctx.base_addr, vm_ctx.vm_addr)

def init_grading(trace):
    """
    评分系统初始化 - 根据地址唯一性赋予初始评分

    原理：出现频率越低的地址(即越"独特"的指令)初始评分越高。
    这是因为VM handler中的循环指令会大量重复，而真正的计算指令往往只出现少数几次。

    算法：
    1. 统计每个地址的出现次数
    2. 按出现次数排序，分配不同等级
    3. 出现次数最少的得最高分
    :param trace: 指令trace
    :return: 带初始评分的trace
    """
    bp()
    # 统计前深拷贝，避免 address_count 内部与外部 trace 状态相互污染
    addr_count = address_count(deepcopy(trace))
    # 不同“出现次数”取值的个数，作为初始分档数量上界
    grade = len(set(i[1] for i in addr_count))
    # 按出现次数升序排列后反转：罕见地址排在列表前部，先赋较高分
    addr_count.reverse()
    ctr = 1
    for tupel in addr_count:  # tupel[0]=地址, tupel[1]=该地址在 trace 中的出现次数
        # 进入新的出现次数档位时整体降一档，使更“拥挤”的地址得分更低
        if ctr != tupel[1]:
            ctr = tupel[1]
            grade -= 1

        # 将该地址对应的所有 trace 行写入当前档位的 grade
        for line in trace:
            if line.addr == tupel[0]:
                line.grade = grade
    return trace


def grading_automaton(visualization=0):
    """
    评分系统分析 - 综合所有分析能力为每行trace自动评分

    评分越高表示该行越可能是被混淆函数的关键指令。
    算法分8个阶段：

    1. 初始化评分(init_grading)：按地址唯一性赋初始分（出现越少分越高）
    2. 寄存器使用频率分类：将寄存器分为重要/不重要两组
    3. 优化预处理：执行常量传播+栈地址传播
    4. 输入/输出分析提升：包含I/O值的行加分，重要寄存器路径加分，不重要寄存器降分
    5. 寄存器频率降分：最常用的寄存器相关行降分，mov/jmp/push/pop等降分
    6. 聚类分析提升：聚类后的单独行(非重复)加分
    7. 窥孔评分：pop/push/inc/dec/lea/test/jmp/mov降分，其他加分
    8. 优化结果提升：优化后存活的行加分，使用内存且非mov的行额外加分

    最后还考虑静态分析结果和递归调用。

    :param visualization: 0=GradingViewer展示, 其他=控制台输出
    :return: 评分后的trace
    """
    vmr = get_vmr()

    w = NotifyProgress('Grading')
    w.show()

    trace = prepare_trace()
    orig_trace = deepcopy(trace)  # 保留未经过本函数内优化的副本，供递归 call 检测与 VM 入口解析
    try:
        # ═══ 阶段1: 初始化评分 ═══
        # 按地址出现频率赋初始分：出现越少分越高
        trace = init_grading(deepcopy(trace))
        w.pbar_update(10) # 10%

        # ═══ 阶段2: 寄存器使用频率分类 ═══
        # 在优化前据第二操作数侧标准寄存器统计频次，划分重要/次要集合供后续 I/O 阶段使用
        reg_dict = defaultdict(lambda: 0)

        # 仅统计 disasm[2] 一侧的标准 CPU 寄存器类，反映 VM 寻址/搬运基础设施
        try:
            for line in trace:
                assert isinstance(line, Traceline)
                if line.is_op2_reg and get_reg_class(line.disasm[2]) is not None:  # 仅 8～16 个标准 GPR 会返回非 None
                    reg_dict[get_reg_class(line.disasm[2])] += 1

            # 按使用频次降序：(寄存器类名, 计数)
            sorted_keys = sorted(reg_dict.items(), key=operator.itemgetter(1), reverse=True)
            length = len(sorted_keys)
            w.pbar_update(10) # 20%
            # 频次高的一半视为“基础设施”寄存器（disregard），低的一半视为更可能携带语义的重要寄存器
            if length % 2 == 0:
                important_regs = set(reg[0] for reg in sorted_keys[:(length / 2)])
                disregard_regs = set(reg[0] for reg in sorted_keys[(length / 2):])
            else:
                # 奇数个时多划一个进次要组，升分保守，避免误标关键路径
                important_regs = set(reg[0] for reg in sorted_keys[:(length - 1) / 2])
                disregard_regs = set(reg[0] for reg in sorted_keys[(length - 1) / 2:])
        except:
            pass


        # ═══ 阶段3: 优化预处理 ═══
        # 常量传播与栈地址传播，使后续 I/O、聚类与 optimize 对齐在同一抽象层上
        try:
            if not trace.constant_propagation:
                trace = optimization_const_propagation(trace)
        except:
            pass
        w.pbar_update(10) #30%
        try:
            if not trace.stack_addr_propagation:
                trace = optimization_stack_addr_propagation(trace)
        except:
            pass

        # ═══ 阶段4: 输入/输出分析提升 ═══
        # 命中推断出的输入/输出值的行加分；沿虚拟寄存器回溯时对重要寄存器路径加薪、次要路径降分
        try:
            values = find_input(deepcopy(trace)).union(find_output(deepcopy(trace)))
            for line in trace:
                for val in values:
                    if val in line.to_str_line():
                        line.raise_grade(vmr.in_out)

            w.pbar_update(10) #40%

            virt_regs = find_virtual_regs(deepcopy(trace))
            for key in virt_regs:
                if get_reg_class(key) in important_regs:
                    for line in follow_virt_reg(deepcopy(trace), virt_reg_addr=virt_regs[key]):
                        try:
                            for other in trace:
                                if line == other:
                                    other.raise_grade(vmr.in_out)
                        except ValueError:
                            print 'The line %s was not found in the trace, hence the grade could not be raised properly!' % line.to_str_line()
                elif get_reg_class(key) in disregard_regs:
                    for line in follow_virt_reg(deepcopy(trace), virt_reg_addr=virt_regs[key]):
                        try:
                            for other in trace:
                                if line == other:
                                    other.lower_grade(vmr.in_out)
                        except ValueError:
                            print 'The line %s was not found in the trace, hence the grade could not be lowered properly!' % line.to_str_line()
        except:
            pass
        w.pbar_update(5) #45%

        # ═══ 阶段5: 寄存器频率降分 ═══
        # 结合第一操作数侧频次重划“高频次要”寄存器，并对 mov/jmp/push/pop 等模板指令统一降分
        try:
            for line in trace:
                assert isinstance(line, Traceline)
                if line.is_op1_reg and get_reg_class(line.disasm[1]) is not None:
                    reg_dict[get_reg_class(line.disasm[1])] += 1

            sorted_keys = sorted(reg_dict.items(), key=operator.itemgetter(1), reverse=True)
            length = len(sorted_keys)
            w.pbar_update(5) #50%
            # 再次出现次数多的一半视为高频“账簿”寄存器，相关行倾向降分
            if length % 2 == 0:
                disregard_regs = set(reg[0] for reg in sorted_keys[:(length / 2)])
            else:
                disregard_regs = set(reg[0] for reg in sorted_keys[:(length - 1) / 2])


            for line in trace:
                assert isinstance(line, Traceline)
                if line.is_jmp or line.is_mov or line.is_pop or line.is_push or line.disasm[0].startswith('ret') or line.disasm[
                    0].startswith('inc') or line.disasm[0].startswith('lea'):
                    line.lower_grade(vmr.pa_ma)
                elif len(line.disasm) > 1 and get_reg_class(line.disasm[1]) in disregard_regs:
                    line.lower_grade(vmr.pa_ma)
        except:
            pass
        w.pbar_update(10) #60%

        # ═══ 阶段6: 聚类分析提升 ═══
        # 对重复聚类结果中单独出现的 Traceline（非块内重复行）提高评分
        try:
            cluster_result = repetition_clustering(deepcopy(trace))
            for line in cluster_result:
                if isinstance(line, Traceline):
                    trace[trace.index(line)].raise_grade(vmr.clu)
        except:
            pass
        w.pbar_update(10) #70%

        # ═══ 阶段7: 窥孔评分 ═══
        # 典型栈调度/比较/跳转类指令降分，其余（更可能为“真”运算）略加分
        try:
            for line in trace:
                assert isinstance(line, Traceline)
                if line.disasm[0] in ['pop', 'push', 'inc', 'dec', 'lea', 'test'] or line.disasm[0].startswith('c') or line.is_jmp or line.is_mov or line.disasm[0].startswith('r'):
                    line.lower_grade(vmr.pa_ma)
                elif len(line.disasm) > 1 and get_reg_class(line.disasm[1]) > 4:
                    continue
                else:
                    line.raise_grade(vmr.pa_ma)
        except:
            pass
        w.pbar_update(10) #80%

        # ═══ 阶段8: 优化结果提升 ═══
        # 与 optimize 后仍保留的行对齐并加薪；非 mov 的内存访问额外奖励
        try:
            opti_trace = optimize(deepcopy(trace))
            w.pbar_update(10) #90%
            for line in opti_trace:
                assert isinstance(line, Traceline)
                try:  # 优化后 trace 结构变化大，原行可能无法按对象相等找回
                    trace[trace.index(line)].raise_grade(vmr.pa_ma)
                except:
                    pass
                # 内存操作且非简单 mov，更可能参与真实 VM 语义
                if line.disasm_len == 3 and line.is_op1_mem and not line.is_mov:
                    try:
                        trace[trace.index(line)].raise_grade(vmr.mem_use)
                    except:
                        pass
                else:
                    trace[trace.index(line)].lower_grade(vmr.pa_ma)
        except:
            pass
        w.pbar_update(5)

        ### STATIC OPTIMIZATION BASED ###
        # 将 IDA 注释中的虚拟指令前缀与 trace 助记符对齐，给已静态标定的行加薪（临时桥接）
        try:
            comments = set(v_inst.split(' ')[0] for v_inst in [Comment(ea) for ea in range(vmr.code_start, vmr.code_end)] if v_inst is not None)
            print comments
            ins = [c.lstrip('v').split('_')[0] for c in comments]
            for line in trace:
                if line.disasm[0] in ins:
                    line.raise_grade(vmr.static)

        except:
            pass
        w.pbar_update(5)

        ### RECURSION ###
        # 从原始 trace 定位 VM 入口地址，并统计对自身的递归调用次数（供后续把相关 call/ss: 行拉到最高分档）
        try:
            recursion = 0
            vm_func = find_vm_addr(orig_trace)
            for line in orig_trace:
                if line.disasm[0].startswith('call') and line.disasm[1].__contains__(vm_func):
                    recursion = recursion + 1
        except:
            pass
        w.close()

        grades = set([line.grade for line in trace])
        max_grade = max(grades)
        # 调用 VM 自身或涉及 ss: 的行视为框架关键，统一提到最高档
        try:
            for line in trace:
                if line.disasm[0].startswith('call') and line.disasm[1].__contains__(vm_func):
                    line.grade = max_grade
                elif line.disasm[1].__contains__('ss:') or line.disasm[2].__contains('ss:'):
                    line.grade = max_grade
        except:
            pass


        if visualization == 0:
            v = GradingViewer(trace, save=save)
            v.Show()
        else:
            threshold = AskLong(1, 'There are a total of %s grades: %s. Specify a threshold which lines to display:' % (len(grades), ''.join('%s ' % c for c in grades)))
            if threshold > -1:
                for line in trace:
                    if line.grade >= threshold:
                        print line.grade, line.to_str_line()

    except Exception, e:
        w.close()
        msg(e.message + '\n')