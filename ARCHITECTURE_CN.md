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

### 5.1 虚拟指令识别 (VmInstruction)

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
