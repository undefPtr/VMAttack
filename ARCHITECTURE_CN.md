# VMAttack 项目架构文档

## 1. 项目概述

**VMAttack** 是一个 IDA Pro 插件，用于对抗**虚拟化混淆（virtualization-based obfuscation）**。它通过静态和动态分析手段，辅助逆向工程师还原被虚拟机保护器（如 VMProtect）混淆的二进制程序。

- **开发语言**: Python 2.7 + IDA Python API
- **依赖库**: distorm3（反汇编引擎）、idacute（Qt兼容层）
- **运行环境**: IDA Pro >= 6.6, Windows 7/10
- **当前版本**: 0.2

## 2. 目录结构

```
VMAttack/
├── VMAttack.py                  # 主控制器（插件入口+管理器）
├── VMAttack_plugin_stub.py      # IDA加载桩文件
├── bp.py                        # 辅助调试模块
├── setup.py                     # 安装脚本
│
├── static/                      # 静态分析模块
│   ├── __init__.py
│   └── static_deobfuscate.py    # 静态反混淆核心
│
├── dynamic/                     # 动态分析模块
│   ├── __init__.py
│   ├── dynamic_deobfuscate.py   # 动态分析调度中心
│   ├── TraceRepresentation.py   # Trace/Traceline数据结构
│   ├── DebuggerHandler.py       # Trace加载/保存
│   ├── Debugger.py              # 调试器基类
│   ├── IDADebugger.py           # IDA调试器实现
│   ├── OllyDebugger.py          # OllyDbg适配
│   └── ImmunityDebugger.py      # ImmunityDbg适配
│
├── lib/                         # 基础库
│   ├── __init__.py
│   ├── Instruction.py           # x86指令封装(distorm3)
│   ├── VmInstruction.py         # 虚拟指令识别(15种)
│   ├── PseudoInstruction.py     # 伪指令IR定义
│   ├── Optimize.py              # 伪指令优化管线(10步)
│   ├── TraceOptimizations.py    # Trace优化算法(5种)
│   ├── TraceAnalysis.py         # Trace分析算法
│   ├── VMRepresentation.py      # 全局状态单例
│   ├── Register.py              # 寄存器分类工具
│   ├── StartVal.py              # 32/64位全局配置
│   ├── Util.py                  # 通用工具函数
│   ├── Logging.py               # 日志系统
│   └── log.py                   # 日志辅助
│
├── ui/                          # UI层
│   ├── __init__.py
│   ├── UIManager.py             # UI管理器(Qt4/Qt5兼容)
│   ├── GradingViewer.py         # 评分结果查看器
│   ├── ClusterViewer.py         # 聚类分析查看器
│   ├── OptimizationViewer.py    # 优化分析查看器
│   ├── VMInputOutputViewer.py   # 输入/输出分析查看器
│   ├── StackChangeViewer.py     # 栈变化查看器
│   ├── BBGraphViewer.py         # 抽象VM控制流图
│   ├── PluginViewer.py          # 插件查看器基类
│   ├── SettingsWindow.py        # 设置窗口
│   ├── AboutWindow.py           # 关于窗口
│   ├── NotifyProgress.py        # 进度条
│   └── legacyUI/                # IDA 6.6-6.8兼容UI
│
├── Example/                     # 示例二进制和trace
│   ├── addvmp/                  # 加法示例
│   ├── sub/                     # 减法示例
│   ├── mulvmp/                  # 乘法示例
│   └── div/                     # 除法示例
│
└── screenshots/                 # README截图
```

## 3. 架构分层

```
┌─────────────────────────────────────────────────────────┐
│                    IDA Pro 宿主环境                       │
├─────────────────────────────────────────────────────────┤
│  VMAttack_plugin_stub.py → VMAttack.py (PLUGIN_ENTRY)   │  入口层
│       VMAttack(plugin_t)    VMAttack_Manager(单例)       │
├──────────┬──────────────┬────────────┬──────────────────┤
│ static/  │   dynamic/   │    lib/    │       ui/        │
│ 静态分析  │   动态分析    │   基础库    │      UI层        │
├──────────┼──────────────┼────────────┼──────────────────┤
│ distorm3 │  IDA Debugger│  Register  │  Qt4(PySide)/    │
│ IDA API  │  API         │  Util      │  Qt5(PyQt5)      │
└──────────┴──────────────┴────────────┴──────────────────┘
```

## 4. 核心数据流

### 4.1 静态分析数据流

```
VM字节码(二进制数据)
    │
    ├─ calc_code_addr() ─→ 查跳转表获取handler地址
    │
    ├─ get_instruction_list() ─→ 反汇编handler为x86指令
    │   返回: List[Instruction]
    │
    ├─ VmInstruction() ─→ 模式匹配识别虚拟指令
    │   输出: vpush/vpop/vadd/vnor/vjmp/vret等
    │
    ├─ add_ret_pop() + make_pop_push_rep() ─→ 转为push/pop伪指令
    │   输出: List[PseudoInstruction] (带临时变量T_xx)
    │
    ├─ optimize() ─→ 10步优化管线
    │   输出: 精简后的伪指令列表
    │
    ├─ find_basic_blocks() ─→ 划分基本块
    │
    └─ show_graph() ─→ 抽象VM控制流图
```

### 4.2 动态分析数据流

```
IDA调试器执行
    │
    ├─ gen_instruction_trace() ─→ 生成指令trace
    │   输出: Trace[Traceline(thread_id, addr, disasm, ctx)]
    │
    ├─ 优化预处理
    │   ├─ optimization_const_propagation() ─→ 常量传播
    │   └─ optimization_stack_addr_propagation() ─→ 栈地址传播
    │
    ├─ 分析
    │   ├─ repetition_clustering() ─→ 聚类分析
    │   ├─ find_input() / find_output() ─→ I/O分析
    │   ├─ find_virtual_regs() + follow_virt_reg() ─→ 虚拟寄存器回溯
    │   └─ grading_automaton() ─→ 综合评分(8阶段)
    │
    └─ 展示
        ├─ GradingViewer ─→ 评分结果(支持阈值过滤)
        ├─ ClusterViewer + StackChangeViewer ─→ 聚类结果
        ├─ OptimizationViewer ─→ 交互式优化
        └─ VMInputOutputViewer ─→ I/O追踪结果
```

## 5. 核心模块详解

### 5.1 Instruction 类：x86 指令适配层

#### 5.1.1 设计思路

`Instruction` 类（`lib/Instruction.py`）是静态反混淆管线的**第一层抽象**，采用**适配器模式**将底层反汇编引擎 distorm3 的原始输出封装为面向 VM 分析领域的语义查询接口。

设计目标有三个：
1. **隔离底层引擎**：上层代码不直接调用 distorm3 API，便于将来替换为 capstone 等其他引擎
2. **提供 VM 领域语义**：将"这条 x86 指令在 VM 分析中意味着什么"封装为 `is_catch_instr()`、`is_write_stack()` 等方法
3. **统一 32/64 位差异**：构造时根据全局 `SV.dissassm_type` 自动选择解码模式，查询方法同时处理 EBP/RBP、ESI/RSI 等差异

#### 5.1.2 在执行流中的完整生命周期

Instruction 对象**仅在静态分析路径**中产生，在两个地方被创建：

```
用户点击菜单 "Static deobfuscate" 或 "Grading System Analysis"
    │
    ▼
static_deobfuscate() 或 grading_automaton() → deobfuscate()
    │
    ├──→ get_start_push(vm_addr)              ← 创建点①
    │       遍历 VM 函数入口的 push 序列
    │       对每条指令: Instruction(addr, bytes)
    │       返回 List[Instruction]
    │       → to_vpush() 消费 Instruction，产出 List[PseudoInstruction]
    │       ★ Instruction 在此被消费后不再使用
    │
    ├──→ first_deobfuscate(code_start, base, code_end)
    │       逐字节遍历 VM 字节码：
    │       │
    │       ├──→ get_instruction_list(bytecode, base)    ← 创建点②
    │       │       calc_code_addr() 查跳转表 → handler 地址
    │       │       循环反汇编 handler 中每条 x86:
    │       │           Instruction(addr, bytes)
    │       │       直到遇到无条件跳转(is_uncnd_jmp)或ret(is_ret)
    │       │       返回 List[Instruction]（一个 handler 的全部 x86 指令）
    │       │
    │       ├── 遍历 List[Instruction] 检测 catch 指令
    │       │       inst.is_catch_instr()  → 是否从字节码流读取参数？
    │       │       inst.is_byte_mov()     → 参数是 1 字节？
    │       │       inst.is_word_mov()     → 参数是 2 字节？
    │       │       inst.is_double_mov()   → 参数是 4 字节？
    │       │       inst.is_quad_mov()     → 参数是 8 字节？
    │       │       inst.get_op_str(1)     → 获取 catch 寄存器名
    │       │
    │       └──→ VmInstruction(instr_lst, catch_value, catch_reg, addr)
    │               ★ List[Instruction] 被传入 VmInstruction
    │               VmInstruction 内部大量调用 Instruction 的查询方法
    │               识别完成后产出 self.Pseudocode (PseudoInstruction)
    │               ★ Instruction 对象作为 VmInstruction.all_instructions 保留
    │                  但后续流程不再直接使用，仅在 __str__ 时用于显示
    │
    ▼
返回 List[VmInstruction] → add_ret_pop() → make_pop_push_rep()
    → List[PseudoInstruction] → optimize() → 基本块 → CFG
    （此后的流程中 Instruction 对象不再参与）
```

#### 5.1.3 两个创建点的区别

| | 创建点① `get_start_push()` | 创建点② `get_instruction_list()` |
|---|---|---|
| **目的** | 解析 VM 函数入口的 push 序列（提取函数参数） | 解析每个字节码对应的 handler 指令序列 |
| **输入** | VM 函数起始地址 `vm_addr` | 字节码值通过跳转表得到的 handler 地址 |
| **终止条件** | 遇到 `mov ebp, esp`（`is_mov_basep_stackp()`） | 遇到无条件跳转（`is_uncnd_jmp()`）或 `ret`（`is_ret()`） |
| **后续消费者** | `to_vpush()` — 直接转为 vpush 伪指令 | `VmInstruction()` — 进行完整的虚拟指令模式匹配 |
| **创建数量** | 少量（通常 5-10 条，仅入口部分） | 大量（每个字节码的 handler 通常 3-15 条 x86 指令） |

#### 5.1.4 VmInstruction 如何消费 Instruction

`VmInstruction.__init__()` 接收 `List[Instruction]` 后，首先将指令分为两组：

```python
for inst in instr_lst:
    if inst.is_vinst():          # 涉及 ESI/RSI 的指令
        self.Vinstructions.append(inst)   # VM 基础设施（字节码指针操作）
    else:
        self.Instructions.append(inst)    # 实际计算逻辑
```

然后调用 `get_pseudo_code()` 依次尝试匹配 15 种虚拟指令模式。每种模式的匹配都**大量依赖 Instruction 的查询方法**，典型的匹配流程如下（以 vpush 为例）：

```
is_push() 匹配流程：
1. 在 Instructions 中寻找 is_sub_basepointer()  → "sub ebp, N" 特征
2. 检查之前是否有 is_cwde()/is_cbw()            → 符号扩展检测
3. 向后搜索 is_write_stack()                     → "mov [ebp], val" 写栈
4. 向前搜索 is_mov()                             → 追溯值的来源
5. 通过 get_op_str()、get_reg_name() 追踪寄存器  → 确定操作数
6. 通过 make_op(inst, op, catch_value)           → 转为 PseudoOperand
7. 构造 PseudoInstruction('vpush', addr, [op])   → 最终产出
```

#### 5.1.5 Instruction 提供的 30+ 查询方法分类

**VM 语义查询**（distorm3 原生不具备，专为 VM 分析设计）：

| 方法 | 语义 | 在 VmInstruction 中的用途 |
|------|------|--------------------------|
| `is_catch_instr()` | 是否通过 ESI/RSI 从字节码流读取参数 | first_deobfuscate 中检测 catch |
| `is_write_stack()` | 是否写入 VM 栈（`mov [ebp], val`） | vpush 识别的核心特征 |
| `is_read_stack()` | 是否读取 VM 栈（`mov val, [ebp]`） | vpop 识别的核心特征 |
| `is_isp_mov()` | 是否修改 VM 指令指针(ESI/RSI) | vjmp 识别的核心特征 |
| `is_vinst()` | 操作数是否涉及 ESI/RSI | 区分 VM 基础设施和计算指令 |
| `is_sub_basepointer()` | 是否 sub ebp/rbp（分配栈空间） | vpush 的入口标志 |
| `is_add_basepointer()` | 是否 add ebp/rbp（释放栈空间） | vpop/vjmp 的入口标志 |
| `is_mov_basep_stackp()` | 是否 `mov ebp, esp` | VM 函数入口检测、栈帧边界 |

**指令类型查询**（封装 distorm3 的 mnemonic/flowControl 判断）：

| 方法 | 查询 | 方法 | 查询 |
|------|------|------|------|
| `is_mov()` | MOV系列 | `is_add()` | ADD |
| `is_push()` | PUSH/PUSHF | `is_pop()` | POP/POPF |
| `is_ret()` | RET | `is_call()` | CALL |
| `is_and()` | AND | `is_not()` | NOT |
| `is_shr()` | SHR | `is_shl()` | SHL |
| `is_shrd()` | SHRD | `is_shld()` | SHLD |
| `is_imul()` | IMUL | `is_idiv()` | IDIV |
| `is_cwde()` | CWDE | `is_cbw()` | CBW |
| `is_cdqe()` | CDQE | `is_uncnd_jmp()` | 无条件跳转 |

**MOV 大小查询**（用于确定 catch 参数的字节数）：

| 方法 | 检测 | 返回的 catch 长度 |
|------|------|------------------|
| `is_byte_mov()` | 操作数 8 位 | 1 字节 |
| `is_word_mov()` | 操作数 16 位 | 2 字节 |
| `is_double_mov()` | 操作数 32 位 | 4 字节 |
| `is_quad_mov()` | 操作数 64 位 | 8 字节 |
| `get_mov_size()` | 自动判断 | 1/2/4/8 字节 |

**操作数访问**（统一接口，被 `make_op()` 用于构造 PseudoOperand）：

| 方法 | 返回 |
|------|------|
| `op_is_reg(n)` | 第 n 个操作数是否为寄存器 |
| `op_is_imm(n)` | 第 n 个操作数是否为立即数 |
| `op_is_mem(n)` | 第 n 个操作数是否为内存引用 |
| `op_is_mem_abs(n)` | 第 n 个操作数是否为绝对地址 |
| `get_op_str(n)` | 操作数的字符串表示 |
| `get_op_size(n)` | 操作数的位宽 |
| `get_op_value(n)` | 立即数的值 |
| `get_op_disp(n)` | 内存引用的偏移量 |
| `get_reg_name(n)` | 寄存器名 |
| `is_rip_rel()` | 是否 RIP 相对寻址 |

#### 5.1.6 三层 IR 转换总结

```
            Instruction               VmInstruction            PseudoInstruction
        ┌─────────────────┐      ┌──────────────────┐     ┌───────────────────────┐
输入 →  │ distorm3 反汇编  │  →   │  模式匹配识别     │  →  │  push/pop 表示         │
        │ 的 x86 指令封装  │      │  虚拟指令类型     │     │  + 临时变量 + 优化     │
        ├─────────────────┤      ├──────────────────┤     ├───────────────────────┤
数据    │ opcode, operands │      │ Pseudocode       │     │ mnem, op_lst,         │
        │ addr, size       │      │ catch_value/reg  │     │ inst_type, inst_class │
        ├─────────────────┤      ├──────────────────┤     ├───────────────────────┤
能力    │ 30+ is_/get_     │      │ 15种 is_xxx()    │     │ make_pop_push_rep()   │
        │ 查询方法          │      │ 模式匹配方法      │     │ 10步 optimize()       │
        ├─────────────────┤      ├──────────────────┤     ├───────────────────────┤
粒度    │ 单条 x86 指令    │      │ 单条 VM 虚拟指令  │     │ 一组 push/pop + 赋值  │
        │                  │      │ (由多条x86组成)   │     │ (由一条VM指令展开)    │
        └─────────────────┘      └──────────────────┘     └───────────────────────┘
               ↑                         ↑                          ↑
          get_instruction_list()    first_deobfuscate()    add_ret_pop() +
          get_start_push()                                 make_pop_push_rep()
```

每层抽象的价值：
- **Instruction**：隔离反汇编引擎、提供 VM 语义查询、统一 32/64 位
- **VmInstruction**：将 3-15 条 x86 指令归约为 1 条 VM 语义指令
- **PseudoInstruction**：引入临时变量使数据流显式化，便于优化和可视化

#### 5.1.7 已知限制

Instruction 类底层依赖 distorm3，存在以下限制：
- distorm3 已停止更新（最新版 3.5.2，2021 年 3 月）
- 不支持 64 位 Python，导致 IDA 7.0+（使用 64 位 Python 3）无法运行静态分析
- 仅支持 x86/AMD64 架构

由于 Instruction 类的适配器设计，如需迁移到 capstone 引擎，只需修改 `Instruction.__init__()` 及内部方法实现，上层的 VmInstruction（117 处调用）和所有依赖模块完全不需要改动。

### 5.2 虚拟指令识别 (VmInstruction)

VM字节码的每个字节通过跳转表映射到一组x86 handler指令。VmInstruction 分析这些指令的模式，识别出15种虚拟指令：

| 虚拟指令 | 识别特征 | 语义 |
|---------|---------|------|
| vpush | sub ebp + mov [ebp], val | VM栈压栈 |
| vpop | mov val, [ebp] + add ebp | VM栈出栈 |
| vadd | add reg1, reg2 (非立即数) | 加法运算 |
| vnor | not + not + and | NOR运算(~a & ~b) |
| vjmp | mov esi, addr + add ebp | VM跳转(修改指令指针) |
| vret | ret | VM函数返回 |
| vread | mov reg, [mem] (非栈) | 内存读取 |
| vwrite | mov [mem], reg (非栈) | 内存写入 |
| vshr/vshl | shr/shl reg1, reg2 | 移位运算 |
| vshrd/vshld | shrd/shld 三操作数 | 双精度移位 |
| vcall | call addr | 函数调用 |
| vimul | imul reg1, reg2 | 有符号乘法 |
| vidiv | idiv reg | 有符号除法 |
| vebp_mov | mov ebp_variant, ebp_variant | 栈帧操作 |

**识别策略**：在handler指令中寻找"特征动作"——例如 `sub ebp` 是 vpush 的标志（分配栈空间），`add ebp` 是 vpop 的标志（释放栈空间）。ESI/RSI 相关的指令被归类为VM基础设施（Vinstructions），不参与虚拟指令识别。

### 5.2 Trace优化算法 (TraceOptimizations)

| 优化名称 | 类型 | 安全性 | 核心原理 |
|---------|------|--------|---------|
| 常量传播 | 传播 | 安全 | 用CPU上下文中的寄存器值替换操作数 |
| 栈地址传播 | 传播 | 安全 | 维护伪栈字典，为栈操作添加值注释 |
| 操作标准化 | 折叠 | 需谨慎 | add x,1→inc x 等标准化替换 |
| 无用操作数折叠 | 折叠 | 需谨慎 | 删除写后未读就被覆盖的操作 |
| 窥孔优化 | 折叠 | 需谨慎 | 删除VM handler高频地址+模式匹配精简 |

### 5.3 评分系统 (Grading Automaton)

评分系统是本插件的核心自动分析能力，通过8个阶段综合评分：

1. **唯一性初始化**：出现频率越低的地址初始分越高
2. **寄存器分类**：将寄存器按使用频率分为重要/不重要两组
3. **优化预处理**：常量传播+栈地址传播
4. **I/O提升**：包含输入/输出值的行加分，重要寄存器路径加分
5. **频率降分**：最常用寄存器相关行降分，mov/jmp/push/pop等降分
6. **聚类提升**：聚类后的单独行（非重复）加分
7. **窥孔评分**：基于指令类型的模式匹配加/降分
8. **优化存活提升**：经过优化后仍存在的行加分

设计特点：**累积评分机制**，单个分析步骤的失败不会导致整体结果错误。用户可通过Settings调整各分析步骤的权重(importance)或将其设为0禁用。

### 5.4 伪指令优化管线 (Optimize)

静态反混淆产生的push/pop伪指令经过10步优化：

```
replace_scratch_variables    # ST_xx → T_xx (栈暂存区→临时变量)
    ↓
replace_push_ebp             # push ebp → 数组操作数(聚合栈上值)
    ↓
replace_pop_push             # push-pop配对 → 直接赋值(T_x = T_y)
    ↓
reduce_assignements          # 赋值传递消减(T2=T1,T3=T2 → T3=T1)
    ↓
convert_read_array           # vread数组 → 简化赋值
    ↓
change_nor_to_not            # vnor(a,a) → vnot(a)
    ↓
reduce_ret                   # 删除vret附近冗余赋值
    ↓
add_comments                 # 标注疑似函数参数(AOS注释)
    ↓
count_left_push/pop          # 计数剩余push/pop
    ↓
delete_overwrote_st          # 删除被覆盖的栈暂存区赋值
```

## 6. 关键设计模式

| 模式 | 应用 | 说明 |
|------|------|------|
| **单例** | VMRepresentation, VMAttack_Manager | 全局唯一的分析状态和管理器 |
| **策略** | available_debuggers列表 | 可插拔的调试器加载策略 |
| **深拷贝隔离** | prepare_trace() + deepcopy | 所有分析操作在trace副本上进行，保护原始数据 |
| **适配器** | UIManager(Qt4↔Qt5) | 兼容IDA SDK 6.6-6.8(PySide)和≥6.9(PyQt5) |
| **多线程** | DynamicAnalyzer(Thread) | 分析步骤可并行执行 |
| **IR分层** | Instruction→VmInstruction→PseudoInstruction | 三层中间表示，逐步抽象 |

## 7. 全局状态 (VMRepresentation)

```python
VMRepresentation (单例)
├── _trace              # 当前指令trace (Trace对象)
├── _vm_ctx             # VM上下文 (VMContext)
│   ├── code_start      #   字节码起始地址
│   ├── code_end        #   字节码结束地址
│   ├── base_addr       #   跳转表基址
│   └── vm_addr         #   VM函数起始地址
├── _vm_operands        # VM函数输入参数 (set)
├── _vm_returns         # VM函数输出值 (dict)
├── _vm_stack_reg_mapping # 栈→寄存器映射 (dict)
├── 评分权重
│   ├── _in_out = 2     #   I/O分析权重
│   ├── _pa_ma = 2      #   模式匹配权重
│   ├── _clu = 1        #   聚类分析权重
│   ├── _mem_use = 3    #   内存使用权重
│   └── _static = 3     #   静态分析权重
└── 环境配置
    ├── _sys_libs        #   是否步入系统库
    ├── _extract_param   #   是否提取函数参数
    ├── _greedy          #   贪心聚类
    ├── _bb              #   显示基本块
    └── _cluster_magic   #   聚类阈值(默认2)
```

## 8. 分析能力总览

| 分析类型 | 名称 | 自动化程度 | 入口函数 |
|---------|------|-----------|---------|
| 自动 | 评分系统分析 | 全自动 | `grading_automaton()` |
| 半自动-静态 | 静态反混淆 | 可能需用户确认 | `static_deobfuscate()` |
| 半自动-静态 | 抽象VM图 | 自动(依赖静态反混淆) | `static_deobfuscate(2)` |
| 半自动-动态 | Trace优化 | 需用户交互选择优化 | `optimization_analysis()` |
| 半自动-动态 | 聚类分析 | 自动展示+用户交互筛选 | `clustering_analysis()` |
| 半自动-动态 | I/O分析 | 自动展示+用户勾选关注值 | `input_output_analysis()` |
| 手动 | VM上下文(静态/动态) | 手动输入或半自动 | `static_vmctx()` / `dynamic_vmctx()` |
| 手动 | 虚拟寄存器跟踪 | 需用户指定寄存器 | `manual_analysis(3)` |
| 手动 | 地址计数 | 自动输出 | `address_heuristic()` |
