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

VM字节码的每个字节通过跳转表映射到一组x86 handler指令。VmInstruction 分析这些指令的模式，识别出15种虚拟指令。

#### 5.2.1 预处理：指令分类

`VmInstruction.__init__()` 首先将 handler 的 `List[Instruction]` 按 ESI/RSI 关联性分为两组：

```
handler 指令列表 (all_instructions)
    │
    ├─ inst.is_vinst() == True  →  Vinstructions  (VM 基础设施：字节码指针移动)
    │                                              不参与模式匹配，仅 vjmp 使用
    │
    └─ inst.is_vinst() == False →  Instructions    (实际计算逻辑)
                                                   所有模式匹配均在此列表上进行
```

然后调用 `get_pseudo_code()` 按优先级依次尝试 15 种模式，**首个匹配成功的即为结果**。

#### 5.2.2 15 种模式匹配算法详解

匹配优先级从上到下（代码中的调用顺序即匹配优先级）：

**① vpush — 压栈** (`is_push`)

```
特征组合: sub ebp, N + mov [ebp], value
    │
    ├─ 在 Instructions 中找到 is_sub_basepointer() → 确认栈指针下移
    │     size = N / 8（分配的字节数 → 即操作数大小）
    │
    ├─ 检查是否有 is_cwde() / is_cbw() → 是否需要符号扩展
    │
    ├─ 向后搜索唯一的 is_write_stack() → mov [ebp], reg
    │     操作数 = 从 reg 向前追踪 mov 链到最终来源
    │
    ├─ 如果 catch_value != -1 → 替换 catch 寄存器为立即数值
    │
    └─ 产出: PseudoInstruction('vpush', addr, [operand], size, PUSH_T)
```

**② vpop — 出栈** (`is_pop`)

```
特征组合: mov value, [ebp] + add ebp, N
    │
    ├─ 在 Instructions 中找到 is_add_basepointer() → 确认栈指针上移
    │     size = N / 8（释放的字节数）
    │
    ├─ 向前搜索 is_read_stack() → mov reg, [ebp]
    │     操作数 = 从 reg 向后追踪 mov 链到最终目的
    │
    ├─ 若无 read_stack → 可能是 popf，检查 add ebp 前的指令
    │
    └─ 产出: PseudoInstruction('vpop'/'vpopf', addr, [operand], size, POP_T)
```

**③ vadd — 加法** (`is_add`)

```
特征: add reg1, reg2（第二操作数非立即数）
    │
    ├─ 在 Instructions 中找到 is_add() 且 NOT op_is_imm(2) → 真正的加法
    │
    ├─ 取 add 的两个操作数，通过 get_reg_name() 获取寄存器名
    │     向前 mov 链追溯两路输入的最终来源
    │
    └─ 产出: PseudoInstruction('vadd', addr, [op0, op1], size, ADD_T, IN2_OUT2)
```

**④ vnor — NOR 运算** (`is_nor`)

```
特征: not reg_a + not reg_b + and reg_a, reg_b（两路取反后逻辑与 = NOR）
    │
    ├─ 寻找 is_and() 指令 → and reg1, reg2
    │
    ├─ 向前追溯：
    │     找到 is_not() 且操作数与 and 的 reg1 同类 → 第一路 not
    │     找到 is_not() 且操作数与 and 的 reg2 同类 → 第二路 not
    │
    ├─ 从两个 not 之前分别向前追溯 mov 链 → 确定原始操作数
    │
    └─ 产出: PseudoInstruction('vnor', addr, [op0, op1], size, NOR_T, IN2_OUT2)
```

**⑤ vjmp — VM 跳转** (`is_jmp`)

```
特征: 在完整 handler（含 Vinstructions）中匹配 ESI/RSI 被更新
    │
    ├─ 遍历 all_instructions（包含 VM 基础设施指令）
    │     找到 is_isp_mov() → mov esi/rsi, reg（更新 VM 指令指针）
    │
    ├─ 同时检查是否有 is_add_basepointer() → add ebp, N
    │     有 → 带有 pop 语义（跳转前弹出地址）
    │
    ├─ 从 ISP mov 的源操作数向前追溯 → 确定跳转目标
    │
    └─ 产出: PseudoInstruction('vjmp', addr, [target], size, JMP_T, IN1_OUT0)
```

**⑥ vwrite — 内存写** (`is_write`)

```
特征: mov [mem], reg（目的为内存，但不是 VM 栈 is_write_stack）
    │
    ├─ 找到 is_mov() 且 op_is_mem(1) 且 NOT is_write_stack()
    │     排除 VM 栈操作，确保是对外部内存的写入
    │
    ├─ 追溯写入地址（op1 的内存引用链）和写入数据（op2 的 mov 链）
    │
    └─ 产出: PseudoInstruction('vwrite', addr, [addr_op, data_op], size, WRITE_T, IN2_OUT0)
```

**⑦ vread — 内存读** (`is_read`)

```
特征: mov reg, [mem]（源为内存，但不是 VM 栈 is_read_stack）
    │
    ├─ 找到 is_mov() 且 op_is_mem(2) 且 NOT is_read_stack()
    │
    ├─ 追溯读取地址和读取结果的 mov 链
    │
    └─ 产出: PseudoInstruction('vread', addr, [addr_op], size, READ_T, IN1_OUT1)
```

**⑧ vshr — 逻辑右移** (`is_shift_right`)

```
特征: shr reg_dest, reg_count（双寄存器，dest ≠ count）
    │
    ├─ 找到 is_shr() → shr 指令
    ├─ 两个操作数必须都是寄存器且不同类
    ├─ 向前追溯两路输入的 mov 链
    │
    └─ 产出: PseudoInstruction('vshr', addr, [op0, op1], size, inst_type, IN2_OUT2)
```

**⑨ vshl — 逻辑左移** (`is_shift_left`)

与 vshr 对称，查找 `is_shl()` 指令。

**⑩ vshrd — 双精度右移** (`is_shrd`)

```
特征: shrd reg1, reg2, reg3（三个寄存器操作数，reg1 ≠ reg2）
    │
    ├─ 找到 is_shrd() → shrd 指令
    ├─ 三个操作数分别追溯 mov 链
    │
    └─ 产出: PseudoInstruction('vshrd', addr, [op0, op1, op2], size, inst_type, IN3_OUT2)
```

**⑪ vshld — 双精度左移** (`is_shld`)

与 vshrd 对称，查找 `is_shld()` 指令。

**⑫ vcall — 函数调用** (`is_vcall`)

```
特征: handler 中出现 call 指令
    │
    ├─ 找到 is_call() → call 指令
    ├─ 通过向前 mov 链解析调用目标
    │
    └─ 产出: PseudoInstruction('vcall', addr, [target_op])
```

**⑬ vret — 返回** (`is_vret`)

```
特征: handler 中出现 ret 指令
    │
    ├─ 找到 is_ret()
    │     注: 具体的 pop 恢复寄存器由 add_ret_pop() 后处理
    │
    └─ 产出: PseudoInstruction('vret', addr, [], size, RET_T)
```

**⑭ vimul — 有符号乘法** (`is_imul`)

```
特征: imul reg1, reg2（含隐式 eax 的两路输入）
    │
    ├─ 找到 is_imul() → imul 指令
    ├─ 向前追溯两个操作数的 mov 链
    │
    └─ 产出: PseudoInstruction('vimul', addr, [op0, op1], size, IMUL_T, IN2_OUT3)
```

**⑮ vidiv — 有符号除法** (`is_idiv`)

```
特征: idiv reg（被除数隐含为 edx:eax，除数为 idiv 的操作数）
    │
    ├─ 找到 is_idiv() → idiv 指令
    ├─ 向前追溯 3 个隐式/显式输入
    │
    └─ 产出: PseudoInstruction('vidiv', addr, [op_eax, op_edx, op_divisor], size, DIV_T, IN3_OUT3)
```

**⑯ vebp_mov — 栈帧操作** (`is_mov_ebp`)

```
特征: mov 的两操作数均属于 ebp/rbp 家族
    │
    └─ 产出: PseudoInstruction('vebp_mov', addr, [op0, op1], size, MOV_EBP_T)
```

#### 5.2.3 共用辅助函数

| 函数 | 作用 |
|------|------|
| `get_previous(inst_lst, inst)` | 获取指令在列表中的前一条 |
| `get_subsequent(inst_lst, inst)` | 获取指令在列表中的后一条 |
| `make_op(inst, op_idx, catch_value)` | 将 Instruction 操作数转为 PseudoOperand |
| `extend_signed_catch_val(catch_val, size)` | 将无符号 catch 值按 size 进行有符号扩展 |

所有模式都遵循相同的**向前 mov 链追溯**策略：从特征指令出发，沿 mov 链向前回溯操作数来源，最终转为 PseudoOperand（寄存器/立即数/内存类型）。

### 5.3 PseudoInstruction：中间表示(IR)设计

#### 5.3.1 操作数类型体系

```
Operand (基类)
├── PseudoOperand     — 类x86操作数（寄存器/立即数/内存/引用/指针）
│     ├── REGISTER_T  — 寄存器操作数 (register='eax', size=32)
│     ├── IMMEDIATE_T — 立即数操作数 (val=0x42, size=32)
│     ├── MEMORY_T    — 内存操作数   (register='ebp', displacement=8)
│     ├── REFERENCE_T — 引用操作数   (地址解引用 → '[addr]')
│     └── POINTER_T   — 指针操作数   (地址引用 → '&name')
│
├── ScratchOperand    — VM栈暂存区 (ST_xx)
│     通过 EDI 间接寻址的 VM 内部暂存区
│     由 get_scratch_variable() 自动识别 vpush/vpop 中 [edi+offset] 模式
│     values 字典全局维护所有 ST_xx 的当前值
│
├── VariableOperand   — 临时变量 (T_xx)
│     由 make_pop_push_rep() 在 push/pop 展开时创建
│     全局计数器确保每个 T_N 唯一
│     is_flags=True 时复用上一编号 → FLAGS T_N
│
├── ArrayOperand      — 数组操作数 (A_xx)
│     表示 VM 栈上多个连续值，用于 replace_push_ebp 优化
│     op_val 列表存储各元素的操作数
│
└── DoubleVariable    — 双结果操作数
      用于 vimul(2个结果) / vidiv(2个结果) 的乘除法
      left + right 各为一个 VariableOperand
```

#### 5.3.2 指令类型与 I/O 模式

```
指令类型 (inst_type)              I/O 模式 (inst_class)
─────────────────────            ──────────────────────
PUSH_T    vpush/vpushf           IN2_OUT2  vadd/vnor/vshr/vshl
POP_T     vpop/vpopf             IN2_OUT3  vimul（2输入3输出）
ADD_T     vadd                   IN3_OUT2  vshrd/vshld（3输入2输出）
NOR_T     vnor                   IN3_OUT3  vidiv（3输入3输出）
READ_T    vread                  IN1_OUT1  vread
WRITE_T   vwrite                 IN2_OUT0  vwrite
JMP_T     vjmp                   IN1_OUT0  vjmp
RET_T     vret                   ASSIGNEMENT_T  优化后的赋值形式
MOV_EBP_T vebp_mov
IMUL_T    vimul
DIV_T     vidiv
NOT_T     vnot（优化产物）
UNDEF_T   未识别
NOTHING_T 空/赋值
```

#### 5.3.3 make_pop_push_rep() 展开规则

每种 I/O 模式有固定的展开模板：

```
IN2_OUT2 (vadd/vnor/vshr/vshl):
  vpop T_0          ; 弹出操作数1
  vpop T_1          ; 弹出操作数2
  T_2 = vmnem T_0, T_1  ; 赋值语句
  vpush T_2         ; 压入结果
  vpush FLAGS T_2   ; 压入标志位

IN2_OUT3 (vimul):
  vpop T_0          ; 弹出乘数1
  vpop T_1          ; 弹出乘数2
  T_2:T_3 = vimul T_0, T_1  ; 双结果赋值
  vpush T_2         ; 压入低位结果
  vpush T_3         ; 压入高位结果
  vpush FLAGS       ; 压入标志位

IN3_OUT3 (vidiv):
  vpop T_0          ; 弹出被除数高位
  vpop T_1          ; 弹出被除数低位
  vpop T_2          ; 弹出除数
  T_3:T_4 = vidiv T_0, T_1, T_2  ; 双结果赋值（商:余数）
  vpush T_4         ; 压入余数
  vpush T_3         ; 压入商
  vpush FLAGS       ; 压入标志位

IN1_OUT0 (vjmp):
  vpop T_0          ; 弹出跳转目标地址
  vjmp T_0          ; 跳转

IN1_OUT1 (vread):
  vpop T_0          ; 弹出读取地址
  T_1 = vread [T_0] ; 从内存读取
  vpush T_1         ; 压入读取值

IN2_OUT0 (vwrite):
  vpop T_0          ; 弹出写入地址
  vpop T_1          ; 弹出写入数据
  [T_0] = vwrite T_1 ; 写入内存
```

### 5.4 Trace 优化算法 (TraceOptimizations)

| 优化名称 | 类型 | 安全性 | 核心原理 |
|---------|------|--------|---------|
| 常量传播 | 传播 | 安全 | 用CPU上下文中的寄存器值替换操作数 |
| 栈地址传播 | 传播 | 安全 | 维护伪栈字典，为栈操作添加值注释 |
| 操作标准化 | 折叠 | 需谨慎 | add x,1→inc x 等标准化替换 |
| 无用操作数折叠 | 折叠 | 需谨慎 | 删除写后未读就被覆盖的操作 |
| 窥孔优化 | 折叠 | 需谨慎 | 删除VM handler高频地址+模式匹配精简 |

### 5.5 评分系统 (Grading Automaton)

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

### 5.6 伪指令优化管线 (Optimize)

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

## 9. 静态反混淆详细流程 (static_deobfuscate.py)

### 9.1 触发入口

用户有三种方式触发静态反混淆，最终都会调用 `deobfuscate()`：

```
IDA 菜单                                       入口函数                    最终调用
──────────────────────────────────────────────────────────────────────────────────────
Semi Automated (static) / Static deobfuscate → static_deobfuscate(0)    → deobfuscate()
Semi Automated (static) / Create VM-Graph    → static_deobfuscate(2)    → deobfuscate(display=2)
Manual Analysis / Deobfuscate from ...       → static_deobfuscate(0,T)  → deobfuscate() (用户输入地址)
Automated Analysis / Grading System          → grading_automaton()      → deobfuscate() (作为子流程)
```

### 9.2 核心编排函数 deobfuscate() 的 10 步流程

```
deobfuscate(code_saddr, base_addr, code_eaddr, vm_addr, display=4, real_start=0)
│
│ ┌─────────────────────────────────────────────────────────────────────┐
│ │ Step 1: 环境初始化                                                   │
│ └─────────────────────────────────────────────────────────────────────┘
├─ set_dissassembly_type()
│     检查 IDA 的 BADADDR 值:
│     0xFFFFFFFFFFFFFFFF → 64位模式 → SV.ASSEMBLER_64
│     其他               → 32位模式 → SV.ASSEMBLER_32
│     影响: Instruction 的 distorm3 解码模式、跳转表项大小(4/8字节)等
│
│ ┌─────────────────────────────────────────────────────────────────────┐
│ │ Step 2: 读取已有 IDA 注释（保留逆向工程师手动标注）                      │
│ └─────────────────────────────────────────────────────────────────────┘
├─ read_in_comments(code_saddr, code_eaddr)
│     遍历字节码地址范围，读取 IDA 中的普通注释和可重复注释
│     返回 List[(comment_text, address)]
│     目的：保留逆向工程师之前手动写入的跳转目标注释（格式: "jumps to: 0xABCD"）
│
│ ┌─────────────────────────────────────────────────────────────────────┐
│ │ Step 3: 确定函数入口地址                                              │
│ └─────────────────────────────────────────────────────────────────────┘
├─ find_start(code_saddr, code_eaddr)
│     在字节码范围内搜索具有交叉引用(cross-reference)的地址
│     若恰好找到 1 个引用点 → 即为函数入口
│     若找不到或多于 1 个  → 回退使用 code_saddr
│
│ ┌─────────────────────────────────────────────────────────────────────┐
│ │ Step 4: 提取 VM 函数入口的 push 序列（函数参数）                        │
│ └─────────────────────────────────────────────────────────────────────┘
├─ get_start_push(vm_addr)
│     从 VM 函数起始地址开始，逐条反汇编 x86 指令（创建 Instruction 对象）
│     直到遇到 "mov ebp, esp" — 表示进入 VM 主循环
│     返回 List[Instruction]（通常是 push reg / push imm 序列）
│
├─ to_vpush(f_start_lst, start_addr)
│     将入口 push 指令转换为 vpush 伪指令:
│     - push reg  → vpush(REGISTER_T, reg_name, size)
│     - push imm  → vpush(IMMEDIATE_T, value, size)
│     - push mem  → vpush(MEMORY_T, mem_expr, size)
│     - pushf     → vpushf(REGISTER_T, "flags", size)
│     返回 List[PseudoInstruction]  ← 函数参数对应的伪指令
│
│ ┌─────────────────────────────────────────────────────────────────────┐
│ │ Step 5: 字节码 → VmInstruction（核心反混淆）                           │
│ └─────────────────────────────────────────────────────────────────────┘
├─ first_deobfuscate(code_saddr, base_addr, code_eaddr)
│     逐字节遍历 [code_saddr, code_eaddr]:
│     │
│     │ ① 读取当前地址的字节值作为字节码 (vc = Byte(addr))
│     │
│     │ ② 查跳转表获取 handler 地址
│     │   calc_code_addr(vc, base):
│     │     32位: handler_addr = Dword(vc × 4 + base)
│     │     64位: handler_addr = Qword(vc × 8 + base)
│     │
│     │ ③ 反汇编 handler 的 x86 指令序列
│     │   get_instruction_list(vc, base):
│     │     从 handler_addr 开始，逐条创建 Instruction(addr, bytes)
│     │     终止条件: 无条件跳转 → 丢弃(回到dispatch循环)
│     │               ret       → 保留(VM函数返回)
│     │     返回 List[Instruction]
│     │
│     │ ④ 检测 catch 指令（读取字节码流中的附加参数）
│     │   遍历 List[Instruction], 调用 inst.is_catch_instr()
│     │   如果找到 catch 指令:
│     │     is_byte_mov()   → catch 1 字节, 总长度 = 2
│     │     is_word_mov()   → catch 2 字节, 总长度 = 3
│     │     is_double_mov() → catch 4 字节, 总长度 = 5
│     │     is_quad_mov()   → catch 8 字节, 总长度 = 9
│     │   没有 catch → 总长度 = 1（单字节操作码）
│     │   ★ catch_value = 从下一字节开始读取对应长度的值
│     │
│     │ ⑤ 构造 VmInstruction
│     │   VmInstruction(instr_lst, catch_value, catch_reg, inst_addr)
│     │     内部流程:
│     │     a) 将指令按 is_vinst() 分为 Vinstructions 和 Instructions
│     │     b) get_pseudo_code() 按优先级尝试匹配 15 种虚拟指令
│     │     c) 匹配成功 → 设置 self.Pseudocode = PseudoInstruction(...)
│     │     d) replace_catch_reg() → 用 catch_value 替换 catch 寄存器
│     │     e) 匹配失败 → Pseudocode = 原始助记符拼接（标记为 UNDEF_T）
│     │
│     │ ⑥ 控制流处理
│     │   若识别为 vjmp 或 vret:
│     │     检查下一地址是否有正常 x86 代码
│     │     → 弹出对话框询问用户：是否继续反混淆该地址？
│     │     → 若否：用户手动输入新的继续地址
│     │     → 记录到 jump_dict 避免重复询问
│     │
│     │ curraddr += length（跳过 catch 参数占用的字节）
│     │
│     返回 List[VmInstruction]
│
│ ┌─────────────────────────────────────────────────────────────────────┐
│ │ Step 6: VmInstruction → push/pop 伪指令表示                          │
│ └─────────────────────────────────────────────────────────────────────┘
├─ add_ret_pop(vm_inst_lst)
│     处理 vret 指令：将其 handler 中的 pop 指令转为 vpop 伪指令
│     （因为 vret 前有一系列 pop 恢复寄存器的操作）
│     返回 List[PseudoInstruction]（包含所有 VmInstruction 的 Pseudocode）
│
├─ make_pop_push_rep()  ← 对每个 PseudoInstruction 调用
│     将高级虚拟指令展开为 push/pop 序列:
│     例: vadd(T1, T2) → vpop T1; vpop T2; vpush (T1 + T2); vpush flags
│     引入临时变量 T_xx 使数据流显式化
│     返回 List[PseudoInstruction]  ← push/pop 粒度
│
│ ┌─────────────────────────────────────────────────────────────────────┐
│ │ Step 7: 跳转地址解析                                                 │
│ └─────────────────────────────────────────────────────────────────────┘
├─ get_jmp_addresses(push_pop_lst, code_eaddr)
│     递归搜索跳转目标:
│     1. 找到所有 JMP_T 类型的伪指令
│     2. 对每个 jmp 指令，调用 start_rec() → rec_find_addr()
│     3. rec_find_addr() 递归回溯数据流:
│        - 操作数是立即数 → 直接作为跳转地址
│        - 操作数是 vpop 的结果 → 找到对应的 vpush，追踪其操作数
│        - 操作数是赋值结果 → 追踪赋值来源
│        - 最大递归深度 20 层
│     4. 如果跳转前有连续 push 立即数 → 可能是跳转表(2+个目标)
│     返回 List[(jump_target_addr, jmp_instruction_addr)]
│
├─ get_jmp_input_found(cjmp_addrs, jmp_addrs)
│     合并自动发现的跳转地址 与 逆向工程师手动标注的跳转地址
│     手动标注优先（覆盖自动发现的结果）
│
│ ┌─────────────────────────────────────────────────────────────────────┐
│ │ Step 8: 基本块划分                                                   │
│ └─────────────────────────────────────────────────────────────────────┘
├─ find_basic_blocks(push_pop_lst, start_addr, jmp_addrs)
│     经典基本块划分算法:
│     1. Leader 收集:
│        - start_addr 是第一个 leader
│        - 每个 JMP_T/RET_T 之后的指令是 leader
│        - 每个跳转目标地址是 leader
│     2. 排序去重 → 相邻 leader 构成 (start, end) 区间
│     返回 List[(bb_start_addr, bb_end_addr)]
│
├─ color_basic_blocks(basic_blocks)
│     在 IDA 中用 6 种颜色循环着色各基本块（视觉辅助）
│
├─ make_bb_lists(push_pop_lst, basic_blocks)
│     按基本块边界将 push_pop_lst 切分为多个子列表
│     返回 List[List[PseudoInstruction]]
│
│ ┌─────────────────────────────────────────────────────────────────────┐
│ │ Step 9: 优化管线（对每个基本块独立执行）                                │
│ └─────────────────────────────────────────────────────────────────────┘
├─ optimize(basic_block_lst, has_loc)   ← 对每个基本块调用
│     10 步优化管线（每步后调用 remove_dropped 清除标记删除的指令）:
│
│     ① replace_scratch_variables
│        将栈暂存区偏移 ST_xx 替换为命名临时变量 T_xx
│        原理: 跟踪 [ebp+offset] 的写入和读取，用 T_N 替代
│
│     ② replace_push_ebp
│        识别 "push ebp" 模式 → 将关联的栈值聚合为数组操作数
│        处理函数有局部变量(has_loc=True)的情况
│
│     ③ replace_pop_push
│        匹配 push-pop 对 → 消除中间栈操作，转为直接赋值
│        算法: 从 pop 向前搜索对应 push（计数配对）
│
│     ④ reduce_assignements
│        赋值链消减: T2 = T1; T3 = T2  →  T3 = T1
│        反复执行直到无变化
│
│     ⑤ convert_read_array
│        将 vread 产生的数组操作数简化为直接赋值
│
│     ⑥ change_nor_to_not
│        语义等价变换: vnor(a, a)  →  vnot(a)
│
│     ⑦ reduce_ret
│        删除 vret 附近对即将丢弃的临时变量的赋值
│
│     ⑧ add_comments
│        为疑似函数参数访问的指令添加 AOS 注释（启发式标注）
│
│     ⑨ count_left_push / count_left_pop
│        计数剩余未消除的 push/pop 指令（诊断信息）
│
│     ⑩ delete_overwrote_st
│        删除后续被覆盖的栈暂存区赋值（dead store elimination）
│
│ ┌─────────────────────────────────────────────────────────────────────┐
│ │ Step 10: 输出展示                                                    │
│ └─────────────────────────────────────────────────────────────────────┘
├─ 根据 display 参数选择输出模式:
│
│   display=0: display_vm_inst()
│     在 IDA 注释中显示原始 VmInstruction（最底层表示）
│
│   display=1: display_ps_inst()
│     在 IDA 注释中显示 push/pop 伪指令（中间表示）
│
│   display>=2: display_ps_inst() + show_graph()
│     在 IDA 注释中显示优化后伪指令
│     构建控制流图:
│       - 节点: 每个非空基本块 → "bb0", "bb1", ...
│       - 边: 根据跳转地址连接基本块
│         - 无 jmp → 顺序连接到下一个基本块
│         - 有 jmp → 连接到所有可能的跳转目标
│         - 有 ret → 无出边
│       - 调用 BBGraphViewer.show_graph() 在 IDA 中渲染 CFG
│
└─ 返回 min_jmp: 所有跳转目标中的最小地址
```

### 9.3 迭代驱动 start()

`deobfuscate()` 外层有一个 `start()` 函数驱动迭代：

```
start(code_saddr, base_addr, code_eaddr, vm_addr, display, real_start)
│
│  old_min = BADADDR
│  n_min = code_saddr
│
│  while old_min > n_min:     ← 不断尝试更小的起始地址
│      old_min = n_min
│      n_min = deobfuscate(old_min, base_addr, code_eaddr, ...)
│                                   ↑ 返回跳转目标的最小地址
│  ★ 循环终止: 当没有发现更小的跳转目标时（说明所有字节码已覆盖）
```

这个机制解决了 VM 字节码中存在**前向跳转**的情况：第一轮可能只处理了部分字节码，但发现有跳转指向更前面的地址，于是从该地址重新开始处理。

### 9.4 VM 上下文自动发现 static_vmctx()

静态反混淆依赖 4 个关键地址（VMContext），`static_vmctx()` 尝试自动发现它们：

```
static_vmctx()
│
├─ 1. 查找 .vmp 段
│     遍历 IDA 段表，寻找名称以 ".vmp" 开头的段
│     获取 vm_seg_start 和 vm_seg_end
│
├─ 2. 查找 VM 函数 (vm_addr)
│     在 .vmp 段内找到最大的函数 → 认定为 VM 解释器主函数
│     原理: VM dispatch 循环通常是段内最大的函数
│
├─ 3. 查找跳转表基址 (base_addr)
│     从 vm_addr 开始向下搜索 jmp 指令
│     匹配模式: jmp [off_XXXXXXXX + reg*scale]
│     提取 off_XXXXXXXX 即为跳转表基址
│     若匹配失败 → 弹出对话框请用户手动输入
│
├─ 4. 查找字节码范围 (code_start, code_end)
│     code_end = vm_seg_end
│     code_start = 从段尾向前搜索，找到第一条 jmp 指令的下一地址
│     原理: 字节码通常位于 .vmp 段末尾，紧接在最后一条 jmp 之后
│
└─ 写入 VMRepresentation 单例
      vmr.vm_ctx = VMContext(code_start, code_end, base_addr, vm_addr)
```

### 9.5 数据转换链完整示例

以一条 `vadd` 虚拟指令为例，展示从原始字节码到最终优化伪指令的转换过程：

```
第一层: 原始字节码
  地址 0x4000: 字节码值 0x3A

第二层: 跳转表查找
  handler_addr = Dword(0x3A * 4 + base_addr) = 0x401234

第三层: handler 反汇编 → List[Instruction]
  0x401234: mov eax, [ebp]      ← Instruction #1 (is_read_stack → vpop 特征)
  0x401237: add ebp, 4           ← Instruction #2 (is_add_basepointer → vpop 特征)
  0x40123A: add [ebp], eax       ← Instruction #3 (add 非立即数 → vadd 特征)
  0x40123D: pushfd               ← Instruction #4 (保存标志位)
  0x40123E: pop [ebp-4]          ← Instruction #5 (标志位写入VM栈)
  0x401241: sub ebp, 4           ← Instruction #6
  0x401244: jmp dispatch         ← Instruction #7 (丢弃，回到dispatch)

第四层: VmInstruction 模式匹配
  识别为 vadd:
    Pseudocode = PseudoInstruction('vadd', 0x4000, [op_eax, op_ebp_mem])

第五层: make_pop_push_rep() 展开
  vpop  T_1        ; 弹出第一个操作数
  vpop  T_2        ; 弹出第二个操作数
  vpush (T_1+T_2)  ; 压入加法结果
  vpush flags      ; 压入标志位

第六层: optimize() 优化
  经过赋值消减、scratch 替换等优化后:
  T_3 = T_1 + T_2  ; 最终简洁表示
```

## 10. Trace 数据流详解：从采集到优化

### 10.1 Trace 数据结构

```python
Trace (继承自 list)
├── List[Traceline]         # 指令序列（按执行顺序排列）
├── ctx_reg_size            # 寄存器宽度: 32 或 64
└── 5个优化状态标志位
    ├── constant_propagation    = False  # 常量传播已执行？
    ├── stack_addr_propagation  = False  # 栈地址传播已执行？
    ├── standardization         = False  # 操作标准化已执行？
    ├── operand_folding         = False  # 无用操作数折叠已执行？
    └── peephole                = False  # 窥孔优化已执行？

Traceline
├── thread_id   # int    — 线程ID
├── addr        # int    — 指令地址 (如 0x401000)
├── disasm      # list   — 标准化反汇编 ['mov', 'eax', '[ebp+8]']
├── ctx         # dict   — 执行后的全部CPU寄存器值 {'eax':'1A2B', 'ebx':'0', ...}
├── comment     # str    — 分析注释（优化/分析时填充）
└── grade       # int    — 评分值（grading_automaton 使用）
```

注意：ctx 中的值是**字符串形式十六进制**（无 0x 前缀），由 `IDADebugger.convert()` 用 `'%x' % int(value)` 生成。

### 10.2 Trace 的两种获取方式

#### 方式一：IDA 调试器实时采集

```
用户菜单 "Generate Trace"
    │
    ▼
gen_instruction_trace(choice)
    │
    ├─ get_dh(choice) → DebuggerHandler 单例
    │
    └─ DebuggerHandler.gen_instruction_trace()
        │
        ├─ self.dbg.hook_dbg()     ← 注册 IDA 调试回调
        └─ self.dbg.gen_trace()    ← 启动调试执行
              │
              ├─ trace_init()      ← 创建空 Trace(reg_size=32/64)
              ├─ RunTo(BeginEA())  ← 运行到入口
              ├─ EnableTracing(TRACE_STEP, 1) ← 开启单步跟踪
              │
              │  ┌── IDA 调试事件循环 ──────────────────────┐
              │  │ 每执行一条指令 → dbg_trace(tid, ea) 回调  │
              │  │   ① 读取 CPU 全部寄存器 → ctx 字典       │
              │  │   ② 反汇编 GetDisasm(ea) → disconv() 标准化│
              │  │   ③ self.trace.append(Traceline(         │
              │  │        thread_id, addr, disasm, ctx))    │
              │  └──────────────────────────────────────────┘
              │
              ├─ 修正 ctx 偏移
              │   dbg_trace 返回的是执行前的上下文
              │   → 将每行 ctx 替换为下一行的 ctx（即执行后状态）
              │
              └─ return trace → vmr.trace = trace
```

核心回调 `IDADebugger.dbg_trace()` 在每次单步时被 IDA 触发：
- 32位模式读取：eax/ebx/ecx/edx/ebp/esp/eip/edi/esi + 7个标志位
- 64位模式额外读取：r8-r15、rax/rbx/... 替代 eax/ebx/...

#### 方式二：从文件加载

```
用户菜单 "Load Trace"
    │
    └─ DebuggerHandler.load()
        │
        ├─ 弹出文件选择对话框 (支持 .txt 和 .json)
        │
        ├─ 根据文件格式解析（4种格式）：
        │   ├─ .json (VMAttack自有格式)
        │   │     直接反序列化字典 → Traceline 列表
        │   │     保留 comment 和 grade 字段
        │   │
        │   ├─ .txt (IDA Win32Dbg trace)
        │   │     以 "Thread xxx" 开头
        │   │     TSV 格式: thread_id \t segment:addr \t disasm \t regs
        │   │     地址解析支持: 绝对地址/函数名+偏移/loc_标签
        │   │
        │   ├─ Immunity Debugger trace
        │   │     以 "Address\t" 开头
        │   │     thread_id 用函数名的字符码之和代替
        │   │
        │   └─ OllyDbg trace
        │         以 "main\t" 开头，格式类似 Immunity
        │
        ├─ 自动检测 32/64 位
        │   最后一行 ctx 中有 'rax' → 64 位
        │   有 'eax' 无 'rax'     → 32 位
        │
        └─ return trace → vmr.trace = trace
```

### 10.3 从全局状态到优化函数的流转

```
vmr.trace (全局原始数据，由采集/加载写入)
    │
    └─ prepare_trace()
        return deepcopy(vmr.trace)  ← ★ 每次分析都深拷贝，保护原始数据
            │
            │  ┌──────────────────────────────────────────────────────────┐
            │  │ 所有分析/优化操作都在副本上进行，互不影响               │
            │  └──────────────────────────────────────────────────────────┘
            │
            ├─→ grading_automaton() 评分系统
            │     阶段3: optimization_const_propagation(trace)
            │     阶段3: optimization_stack_addr_propagation(trace)
            │     阶段8: optimize(deepcopy(trace))  ← 再次深拷贝
            │
            ├─→ clustering_analysis() 聚类分析
            │     optimization_const_propagation(trace)
            │     optimization_stack_addr_propagation(trace)
            │     repetition_clustering(deepcopy(trace))
            │
            ├─→ input_output_analysis() I/O分析
            │     多线程并行:
            │       DynamicAnalyzer(find_input, trace)
            │       DynamicAnalyzer(find_output, trace)
            │       DynamicAnalyzer(find_virtual_regs, trace)
            │
            ├─→ optimization_analysis() 优化分析
            │     OptimizationViewer(trace, save=save)
            │     用户在UI中手动选择执行哪些优化
            │
            └─→ address_heuristic() 地址频率统计
                  address_count(deepcopy(trace))
```

### 10.4 优化状态标志的使用

每个优化函数执行后设置对应标志位为 True，调用方通过标志位避免重复执行：

```python
# clustering_analysis() 中的典型用法
if not trace.constant_propagation:       # 尚未执行常量传播？
    trace = optimization_const_propagation(trace)    # 执行
# 此后 trace.constant_propagation == True

if not trace.stack_addr_propagation:     # 尚未执行栈地址传播？
    trace = optimization_stack_addr_propagation(trace)
```

完整的 5 种优化执行顺序（由 `optimize()` 函数驱动）：

```
optimizations = [
    optimization_const_propagation,        # ① 常量传播（传播型，安全）
    optimization_stack_addr_propagation,   # ② 栈地址传播（传播型，安全）
    optimization_standard_ops_folding,     # ③ 操作标准化（折叠型，需谨慎）
    optimization_unused_operand_folding,   # ④ 无用操作数折叠（折叠型，需谨慎）
    optimization_peephole_folding          # ⑤ 窥孔优化（折叠型，需谨慎）
]
```

### 10.5 深拷贝隔离策略

项目中大量使用 `deepcopy` 来隔离数据，这是一个重要的设计决策：

| 场景 | deepcopy 层级 | 目的 |
|------|-------------|------|
| `prepare_trace()` | 从 vmr.trace 拷贝 | 保护全局原始 trace 不被分析修改 |
| `DynamicAnalyzer.__init__()` | 入参 trace 再拷贝 | 多线程间互不干扰 |
| `grading_automaton` 阶段8 | trace 再拷贝 | 优化不影响评分阶段的 trace |
| `find_input/output/virtual_regs` | 调用时 deepcopy | 各分析独立运行 |

这意味着即使优化函数会修改 Traceline 的 disasm、comment 字段，或直接删除行（折叠型优化），原始数据始终安全。

## 11. TraceAnalysis 动态分析算法详解

### 11.1 聚类分析 (repetition_clustering)

聚类分析的目标是将 trace 中重复出现的指令序列归组，从而识别出 VM handler 的循环模式。

#### 算法流程

```
repetition_clustering(trace, rounds=None)
│
├─ 输入: Trace 对象（按执行顺序排列的 Traceline 列表）
│
├─ 贪心模式 (rounds=None, 默认):
│     pre = 1, post = 0
│     while pre != post:        ← 直到列表长度不再变化
│         pre = len(cluster)
│         cluster = repetition_cluster_round(cluster)
│         post = len(cluster)
│
├─ 固定轮次模式 (rounds=N):
│     for j in range(N):
│         cluster = repetition_cluster_round(cluster)
│
└─ 返回: 混合列表 [Traceline | List[Traceline]]
         Traceline = 单独行（非重复）
         List[Traceline] = 一个聚类（重复出现的相邻序列）
```

#### 单轮聚类 repetition_cluster_round()

```
1. 将列表中相邻元素两两配对: [(elem_0, elem_1), (elem_2, elem_3), ...]

2. 对每一对 (a, b)：
   检查 a 和 b 在列表中出现次数是否相等
   且满足: count(相邻出现) > cluster_magic (默认=2)

3. 如果满足 → 合并为一个聚类:
   - Traceline + Traceline → [a, b]
   - List + Traceline → list.append(b)
   - Traceline + List → [a] + list
   - List + List → list1.extend(list2)

4. 清理: 删除 BADADDR 的无效行

5. 断言: 合并前后总行数不变（数据完整性检查）
```

### 11.2 VM 上下文动态发现 (dynamic_vm_values)

从运行时 trace 中自动推断 VM 的 4 个关键地址：

```
dynamic_vm_values(trace)
│
├─ 1. 定位 VM 函数 (vm_addr)
│     find_vm_addr(trace):
│       统计每条 push 指令所属函数 → 出现 push 最多的函数
│       验证: 该函数应为所在段中最大的函数（by 代码大小）
│       冲突时弹出对话框让用户选择
│
├─ 2. 提取 VM 段
│     extract_vm_segment(trace):
│       优先按段名 ".vmp" 查找
│       失败则用 vm_addr 所在段
│       仅保留 trace 中地址在段内的行
│
├─ 3. 推断跳转表基址 (base_addr)
│     在 trace 中统计 "off_XXXX[...]" 形式的间接引用
│     取出现频率最高的地址作为候选
│     向前回退到表的真正起始位置（跳过空数据项）
│
├─ 4. 推断字节码起始 (code_start)
│     从 vm_addr 函数末尾向后查找非代码区域起始
│     同时检查 trace 中调用 vm_func 前的 push 参数
│     两者不一致时弹出对话框确认
│
├─ 5. 推断字节码结束 (code_end)
│     默认使用 vm_seg_end（.vmp 段结束地址）
│
└─ 返回: VMContext(code_start, code_end, base_addr, vm_addr)
```

### 11.3 虚拟寄存器映射 (find_virtual_regs)

VM 退出时通过一系列 pop 指令将 VM 栈上的值恢复到真实寄存器。此函数反向分析这些 pop，建立「栈地址 → 真实寄存器」映射。

```
find_virtual_regs(trace)
│
├─ 从 trace 末尾向前遍历（pop 序列在最后）
│
├─ 对每条 pop reg:
│     if reg 是有效寄存器（get_reg_class 非 None）且尚未记录:
│         stack_addr = 上一条指令的 ctx[rsp]  ← pop 前的栈顶
│         virt_regs[reg] = stack_addr
│
└─ 返回: dict { 'eax': 'FF80', 'ebx': 'FF84', ... }
         键 = 真实寄存器名
         值 = VM 栈上对应的地址（十六进制字符串）
```

### 11.4 输入分析 (find_input)

黑盒追踪 VM 函数接收的输入参数值。

```
find_input(trace)
│
├─ 1. 提取 VM 段内 trace
│     extract_vm_segment(deepcopy(trace))
│
├─ 2. 扫描 ss: 前缀操作数
│     trace 中出现 "ss:[reg]" 形式的操作数
│     → 从 ctx 中读取对应寄存器的值 → 加入输入集合
│
├─ 3. 调用约定分析
│     find_ops_callconv(trace, vmp_start, vmp_end):
│       反向搜索调用 VM 函数前的 push 和 mov [esp±...] 指令
│       提取被传递的参数值（寄存器值或立即数）
│
├─ 4. 合并调试器捕获的参数
│     如果 vmr.func_args 非空（由 IDADebugger 在 trace 时提取）
│     直接加入输入集合
│
└─ 返回: set { 'FF', '42', ... }（十六进制值字符串）
```

### 11.5 输出分析 (find_output)

追踪 VM 函数返回时各寄存器的值（输出值）。

```
find_output(trace)
│
├─ 提取 VM 段内 trace，反转
│
├─ 从末尾向前找到第一条 ret 或 pop 指令
│     获取该点的 ctx（CPU 上下文快照）
│
└─ 返回: set { ctx[reg] for each reg where get_reg_class(reg) is not None }
         即所有标准 GPR 寄存器在 VM 退出时的值
```

### 11.6 虚拟寄存器回溯 (follow_virt_reg)

从 VM 出口的某个寄存器值反向追踪其完整计算过程，提取所有参与该计算的 trace 行。

```
follow_virt_reg(trace, virt_reg_addr, real_reg_name)
│
├─ 预处理: 常量传播 + 栈地址传播
│
├─ 反转 trace（从后向前遍历）
│
├─ 初始化:
│     从末尾 pop reg 获取目标值 → reg_vals = {初始值}
│     watch_addrs = {virt_reg_addr}（关注的栈地址）
│
├─ 反向遍历:
│     对每一行:
│       ┌─ 值追踪: 某关注值首次出现在 ctx 中
│       │   ├─ mov from mem → 源地址加入 watch_addrs
│       │   └─ 计算指令 → 操作数的寄存器值加入 reg_vals
│       │     记录该行到 backtrace
│       │
│       └─ 地址监视: 某关注地址被写入
│           记录该行到 backtrace
│           写入数据的值加入 reg_vals
│           如果是 mov → 从 watch_addrs 移除（值已找到来源）
│
├─ 反转 backtrace 回正常顺序
│
├─ 过滤: 移除与 VM 基础设施相关的行
│     (esi/edi/ebp/rsi/rdi/rbp 操作)
│
└─ 返回: Trace 仅包含与目标寄存器计算相关的行
```

#### 回溯策略的核心思想

```
时间轴（正向）:  ────────────────────────────────→
                 mov eax,[ebp+4]  add eax,ebx  pop ecx (ecx=eax的值)
                      ↑                ↑            ↑
                  watch_addr 命中   计算指令      初始种子

回溯方向（反向）: ←────────────────────────────────
                 从 pop 的值出发，沿数据流反向扩展关注集合
```

## 12. Grading Automaton 8 阶段评分算法详解

评分系统是 VMAttack 最核心的自动分析能力，将多种分析手段的结果通过**累积评分机制**融合，自动筛选出 trace 中最可能携带"真实语义"的指令行。

### 12.1 设计哲学

- **累积而非淘汰**：每个阶段独立加分/减分，单个阶段失败不影响整体结果
- **可配置权重**：用户通过 Settings 窗口调整各分析步骤的权重（`vmr.in_out` / `vmr.pa_ma` / `vmr.clu` / `vmr.mem_use` / `vmr.static`），或设为 0 禁用
- **保护原始数据**：所有操作在 `prepare_trace()` 的深拷贝上进行

### 12.2 8 阶段详细流程

```
grading_automaton(visualization=0)
│
│ trace = prepare_trace()           ← 深拷贝 vmr.trace
│ orig_trace = deepcopy(trace)      ← 再拷贝一份供递归检测用
│
│ ═══════════════════════════════════════════════════════════════
│ 阶段 1: 唯一性初始化                                    [10%]
│ ═══════════════════════════════════════════════════════════════
├─ init_grading(trace):
│     统计每个地址出现的次数
│     grade = max_count - 该地址出现次数
│     出现越少（越独特）→ 初始分越高
│     出现最多的地址 → grade = 0
│
│ ═══════════════════════════════════════════════════════════════
│ 阶段 2: 寄存器频率分类                                  [20%]
│ ═══════════════════════════════════════════════════════════════
├─ 统计 disasm[2]（第二操作数侧）出现的寄存器类频率
│     按频率降序排列
│     高频一半 → disregard_regs（VM 基础设施寄存器）
│     低频一半 → important_regs（更可能携带语义的寄存器）
│     奇数个时多划一个到 disregard 组（保守策略）
│
│ ═══════════════════════════════════════════════════════════════
│ 阶段 3: 优化预处理                                      [30%]
│ ═══════════════════════════════════════════════════════════════
├─ if not trace.constant_propagation:
│     trace = optimization_const_propagation(trace)
│  if not trace.stack_addr_propagation:
│     trace = optimization_stack_addr_propagation(trace)
│  目的: 让后续 I/O 分析、聚类、窥孔等在同一抽象层上工作
│
│ ═══════════════════════════════════════════════════════════════
│ 阶段 4: 输入/输出分析提升                               [45%]
│ ═══════════════════════════════════════════════════════════════
├─ values = find_input(trace) ∪ find_output(trace)
│     对 trace 中每一行:
│       if 行的字符串表示包含某个 I/O 值:
│         line.raise_grade(vmr.in_out)           ← 加分
│
├─ virt_regs = find_virtual_regs(trace)
│     对每个虚拟寄存器:
│       if 其真实寄存器 ∈ important_regs:
│         follow_virt_reg() 回溯的每一行 → raise_grade(vmr.in_out)
│       elif 其真实寄存器 ∈ disregard_regs:
│         follow_virt_reg() 回溯的每一行 → lower_grade(vmr.in_out)
│
│ ═══════════════════════════════════════════════════════════════
│ 阶段 5: 寄存器频率降分                                  [60%]
│ ═══════════════════════════════════════════════════════════════
├─ 合并 disasm[1] 侧的寄存器频率到 reg_dict
│     重新排序，高频一半 → disregard_regs
│
├─ 对 trace 中每一行:
│     if jmp/mov/pop/push/ret/inc/lea:
│       line.lower_grade(vmr.pa_ma)              ← 模板指令降分
│     elif disasm[1] 的寄存器类 ∈ disregard_regs:
│       line.lower_grade(vmr.pa_ma)              ← 高频寄存器降分
│
│ ═══════════════════════════════════════════════════════════════
│ 阶段 6: 聚类分析提升                                    [70%]
│ ═══════════════════════════════════════════════════════════════
├─ cluster_result = repetition_clustering(deepcopy(trace))
│     遍历聚类结果:
│       if isinstance(line, Traceline):           ← 单独行（非重复）
│         trace 中对应行 raise_grade(vmr.clu)
│       (聚类内的行不加分 → 重复行自然低分)
│
│ ═══════════════════════════════════════════════════════════════
│ 阶段 7: 窥孔评分                                        [80%]
│ ═══════════════════════════════════════════════════════════════
├─ 对 trace 中每一行:
│     if disasm[0] in [pop,push,inc,dec,lea,test]
│        or jmp or mov or 以 'c'/'r' 开头:
│       line.lower_grade(vmr.pa_ma)              ← 栈调度/跳转类降分
│     elif 第一操作数寄存器编号 > 4:
│       continue                                  ← 高编号寄存器跳过
│     else:
│       line.raise_grade(vmr.pa_ma)              ← 其余（运算类）加分
│
│ ═══════════════════════════════════════════════════════════════
│ 阶段 8: 优化存活提升                                    [90%]
│ ═══════════════════════════════════════════════════════════════
├─ opti_trace = optimize(deepcopy(trace))
│     对 opti_trace 中每一行:
│       trace 中找到对应行 → raise_grade(vmr.pa_ma)
│       if 内存操作且非 mov:
│         raise_grade(vmr.mem_use)               ← 内存运算额外加分
│       else:
│         lower_grade(vmr.pa_ma)                 ← 简单指令微降
│
│ ═══════════════════════════════════════════════════════════════
│ 附加: 静态分析交叉验证                                  [95%]
│ ═══════════════════════════════════════════════════════════════
├─ 从 IDA 注释中提取已静态标注的虚拟指令前缀
│     对 trace 中助记符命中的行:
│       raise_grade(vmr.static)
│
│ ═══════════════════════════════════════════════════════════════
│ 附加: 递归调用检测                                      [100%]
│ ═══════════════════════════════════════════════════════════════
├─ find_vm_addr(orig_trace) → 定位 VM 函数地址
│     检测 trace 中对 VM 函数的 call 次数
│     如果存在递归调用 → 记录（可供 UI 提示用户）
│
└─ 输出:
     visualization=0 → GradingViewer UI 展示（支持阈值过滤）
     其他           → 控制台输出
```

### 12.3 评分权重体系

| 权重变量 | 默认值 | 影响阶段 | 含义 |
|---------|--------|---------|------|
| `vmr.in_out` | 2 | 阶段4 | 输入/输出命中的加/降分幅度 |
| `vmr.pa_ma` | 2 | 阶段5/7/8 | 模式匹配/窥孔/优化存活的加/降分幅度 |
| `vmr.clu` | 1 | 阶段6 | 聚类分析中单独行的加分幅度 |
| `vmr.mem_use` | 3 | 阶段8 | 内存运算的额外加分幅度（最高权重） |
| `vmr.static` | 3 | 附加 | 静态分析交叉验证的加分幅度 |

设为 0 可完全禁用对应分析步骤的影响。

### 12.4 GradingViewer 阈值过滤

评分完成后，GradingViewer 按以下策略展示结果：

```
threshold = grade_max * (percentage / 100)

对 trace 中每一行:
  if line.grade >= threshold:
    展示（高亮显示）
  else:
    仅在 grade > 0 时作为上下文行显示（不高亮）
```

用户可通过滑动条调整 percentage（0-100%），实时筛选不同置信度的结果。
