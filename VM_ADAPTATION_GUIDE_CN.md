# VMAttack 适配指南：面对不同 VM 实现的应对策略

## 前言

VMAttack 最初针对特定的 VM 保护方案（类 VMProtect 架构）设计，代码中硬编码了大量关于 VM 结构的假设。当面对不同的 VM 实现时，需要理解这些假设并有针对性地修改。

本文档将系统梳理：
1. 当前代码的全部 VM 假设
2. 不同 VM 实现中常见的变体
3. 每类变体的具体修改方案
4. 一个实际适配的工作流程

## 1. 当前架构的 VM 模型假设

VMAttack 假设的 VM 是一个**栈机器**，具有以下固定结构：

```
┌─────────────────────────────────────────────────────────┐
│                    VM 解释器主循环                         │
│                                                           │
│  vm_addr:                                                 │
│    push reg1          ← 保存寄存器（入口 push 序列）       │
│    push reg2                                              │
│    ...                                                    │
│    mov ebp, esp       ← 建立 VM 栈帧                      │
│                                                           │
│  dispatch:                                                │
│    movzx eax, byte [esi]   ← 读取操作码（单字节）          │
│    jmp [base + eax*4]      ← 跳转表分发                   │
│                                                           │
│  handler_XX:                                              │
│    ... (3-15条x86指令)     ← 执行 VM 操作                 │
│    jmp dispatch            ← 回到主循环                   │
│                                                           │
│  handler_ret:                                             │
│    pop reg1                ← 恢复寄存器                   │
│    pop reg2                                               │
│    ret                     ← 返回原始代码                 │
│                                                           │
│  字节码区:                                                 │
│    db opcode, [catch_bytes], opcode, [catch_bytes], ...   │
│                                                           │
│  跳转表:                                                   │
│    dd handler_00, handler_01, ..., handler_FF             │
│                                                           │
└─────────────────────────────────────────────────────────┘
```

### 1.1 硬编码的寄存器角色

| 角色 | 绑定寄存器 | 使用位置 | 常量/方法 |
|------|-----------|---------|-----------|
| VM 指令指针 (VPC) | **ESI / RSI** | `Instruction.is_catch_instr()`, `is_vinst()`, `is_isp_mov()` | 硬编码 `'ESI'/'RSI'` 字符串比较 |
| VM 栈指针 (VSP) | **EBP / RBP** | `is_write_stack()`, `is_read_stack()`, `is_sub_basepointer()`, `is_add_basepointer()`, `is_mov_basep_stackp()` | 硬编码 `'EBP'/'RBP'` 字符串比较 |
| VM 暂存区 | **EDI** | `PseudoInstruction.get_scratch_variable()` | 通过 `get_reg_class('edi')` 判断 |
| 宿主栈指针 | **ESP / RSP** | `TraceAnalysis.find_virtual_regs()`, `follow_virt_reg()` | 通过 `get_reg('rsp', ...)` |

### 1.2 硬编码的字节码结构

| 假设 | 详情 | 代码位置 |
|------|------|---------|
| 单字节操作码 | `Byte(curraddr)` 读取 | `static_deobfuscate.py:194` |
| 256 种 handler | `deobfuscate_all` 遍历 0x00-0xFF | `static_deobfuscate.py:292` |
| 线性跳转表 | `handler = Dword(opcode * 4 + base)` | `static_deobfuscate.py:calc_code_addr()` |
| catch 紧跟操作码 | 长度 1/2/4/8 字节 | `static_deobfuscate.py:208-237` |
| handler 以 jmp 结尾 | jmp dispatch 回主循环 | `static_deobfuscate.py:get_instruction_list()` |
| 小端序 | IDA 默认 `Byte/Word/Dword/Qword` | 全局 |

### 1.3 硬编码的 VM 定位假设

| 假设 | 详情 | 代码位置 |
|------|------|---------|
| .vmp 段名 | `SegName.startswith('.vmp')` | `static_deobfuscate.py:static_vmctx()`, `TraceAnalysis.py:extract_vm_segment()` |
| 段内最大函数 = VM 主循环 | 按代码大小排序 | `static_deobfuscate.py:static_vmctx()`, `TraceAnalysis.py:find_vm_addr()` |
| 跳转表形式 | `jmp [off_XXXX + reg*scale]` | `static_deobfuscate.py:static_vmctx()`, `TraceAnalysis.py:dynamic_vm_values()` |
| 字节码在段尾 | 从函数末尾到段结束 | `static_deobfuscate.py:static_vmctx()` |

## 2. 常见 VM 变体与适配方案

### 2.1 变体一：不同的寄存器分配

**问题**：VM 使用其他寄存器作为 VPC/VSP。例如 R13 作为栈指针，R14 作为指令指针。

**修改方案**：

```
步骤 1: 修改 lib/Instruction.py（最底层）

需修改的方法及对应的寄存器：

┌──────────────────────────┬──────────────────┬──────────────────────┐
│ 方法                      │ 当前假设          │ 需改为                │
├──────────────────────────┼──────────────────┼──────────────────────┤
│ is_catch_instr()          │ ESI/RSI          │ 目标 VM 的 VPC 寄存器 │
│ is_vinst()                │ ESI/RSI          │ 同上                 │
│ is_isp_mov()              │ ESI/RSI          │ 同上                 │
│ is_write_stack()          │ EBP/RBP          │ 目标 VM 的 VSP 寄存器 │
│ is_read_stack()           │ EBP/RBP          │ 同上                 │
│ is_sub_basepointer()      │ EBP/RBP          │ 同上                 │
│ is_add_basepointer()      │ EBP/RBP          │ 同上                 │
│ is_mov_basep_stackp()     │ EBP+ESP/RBP+RSP  │ 对应的栈帧建立指令    │
└──────────────────────────┴──────────────────┴──────────────────────┘

推荐做法: 将寄存器名参数化
  在 lib/StartVal.py 中添加:
    VM_STACK_REG = 'EBP'     # 或 'R13'
    VM_PC_REG = 'ESI'        # 或 'R14'
    VM_SCRATCH_REG = 'EDI'   # 或 'R15'
  
  修改 Instruction 中的判断为:
    reg_name == SV.VM_STACK_REG or reg_name == SV.VM_STACK_REG.replace('E','R')

步骤 2: 修改 lib/VmInstruction.py

VmInstruction 的 is_push/is_pop/is_jmp 等方法都依赖 Instruction 的查询方法，
如果步骤1修改正确，这里通常不需要额外修改。

步骤 3: 修改 lib/TraceAnalysis.py

follow_virt_reg() 末尾的过滤列表:
  当前: ['esi', 'edi', 'ebp', 'rsi', 'rdi', 'rbp']
  改为: 包含目标 VM 使用的所有基础设施寄存器
```

### 2.2 变体二：不同的字节码编码

**问题**：操作码不是单字节，或跳转表不是线性数组。

**常见变体**：

| 变体 | 描述 | 常见于 |
|------|------|--------|
| 双字节操作码 | `Word(addr)` 读取 | 大操作码空间的 VM |
| 变长操作码 | 高位决定后续长度 | 压缩编码的 VM |
| 哈希分发 | `handler = hash(opcode)` | 抗模式匹配的 VM |
| Switch-case | cmp+jcc 链 | 简单保护方案 |
| Call 表 | `call [table + opcode*4]` | 非标准分发 |

**修改方案**：

```
步骤 1: 修改 static_deobfuscate.py 中的字节码遍历

calc_code_addr(instr, base):
  当前: handler = Dword(instr * 4 + base)
  
  双字节操作码:
    instr = Word(curraddr)  # 代替 Byte(curraddr)
    handler = Dword(instr * 4 + base)  # 表项数量可能 > 256

  哈希分发:
    需要逆向哈希函数，替换整个 calc_code_addr
    或：用动态 trace 获取 (opcode → handler) 的映射

  Switch-case:
    无法使用跳转表遍历
    需要改为对每个 case 分支提取 handler 地址

步骤 2: 修改 first_deobfuscate() 中的 catch 长度计算

当前假设 catch 紧跟操作码:
  length = 1 (无 catch) / 2 / 3 / 5 / 9

可能的变体:
  - catch 在操作码之前
  - catch 与操作码之间有填充
  - 多个 catch 值（多参数指令）

步骤 3: 修改 deobfuscate_all()

当前遍历 0x00-0xFF (256 种):
  for instr in range(256):
      get_instruction_list(instr, base)

双字节操作码:
  for instr in range(65536):  # 或实际表大小
      get_instruction_list(instr, base)
```

### 2.3 变体三：不同的 Handler 结构

**问题**：Handler 不以 `jmp dispatch` 结尾，或有多个出口。

**常见变体**：

| 变体 | 终止方式 | 示例 |
|------|---------|------|
| Fall-through | Handler 间无显式跳转 | 顺序执行到下一个 handler |
| Call dispatch | `call dispatch_func` | 通过调用而非跳转回到分发 |
| 条件结尾 | `jcc xxx; jmp dispatch` | 带条件分支的 handler |
| 内联 dispatch | Handler 自带 fetch+dispatch | 无集中的 dispatch 循环 |

**修改方案**：

```
核心修改: get_instruction_list() 的终止条件

当前逻辑:
  while True:
    inst = Instruction(addr, bytes)
    if inst.is_uncnd_jmp():
      break       # jmp → 结束，丢弃 jmp
    if inst.is_ret():
      list.append(inst)
      break       # ret → 结束，保留 ret
    list.append(inst)

适配不同终止方式:

  Fall-through:
    需要预知每个 handler 的边界
    通常通过跳转表分析确定所有 handler 起始地址
    handler_end = min(next_handler_start, current + MAX_HANDLER_SIZE)

  Call dispatch:
    if inst.is_call() and call_target == dispatch_addr:
      break  # 类似 jmp，丢弃 call

  条件结尾:
    收集所有分支目标
    if target == dispatch_addr:
      continue  # 条件回 dispatch 不终止
    else:
      记录为 VM 跳转目标

  内联 dispatch:
    需要识别 "fetch next opcode" 模式
    (通常是 mov reg, [VPC] 后接跳转表查找)
```

### 2.4 变体四：不同的栈操作模式

**问题**：VM 栈不使用 `sub ebp / add ebp` 模式。

**常见变体**：

| 变体 | 栈操作方式 | 特征 |
|------|-----------|------|
| 标准（当前） | sub ebp, N → push; add ebp, N → pop | VSP 向低地址增长 |
| 反向增长 | add ebp → push; sub ebp → pop | VSP 向高地址增长 |
| 指针递增 | lea ebp, [ebp+N] | 使用 lea 代替 add/sub |
| 独立入栈出栈 | push/pop 直接操作 | 使用 x86 原生栈指令 |
| 双栈 | 两个栈指针 | 数据栈 + 返回栈分离 |

**修改方案**：

```
步骤 1: 修改 Instruction.py 的栈操作判断

反向增长:
  is_sub_basepointer() → 改为 vpop 的标志
  is_add_basepointer() → 改为 vpush 的标志
  （交换 VmInstruction.is_push 和 is_pop 中的角色）

lea 模式:
  新增 is_lea_basepointer() 方法
  在 VmInstruction 的匹配中替代 sub/add

独立栈操作:
  直接识别 push/pop x86 指令作为 VM 操作
  可能不需要 VmInstruction 层的复杂匹配

步骤 2: 修改 VmInstruction.py

is_push():
  当前: 找 is_sub_basepointer + is_write_stack
  改为: 找目标 VM 对应的栈增长+写入模式

is_pop():
  当前: 找 is_read_stack + is_add_basepointer
  改为: 找目标 VM 对应的读取+栈缩减模式
```

### 2.5 变体五：不同的 VM 定位方式

**问题**：VM 代码不在 `.vmp` 段中，或结构与假设不同。

**修改方案**：

```
方案 A: 使用 Settings 窗口手动输入

VMAttack 已支持通过 SettingsWindow 手动设置 4 个 VMContext 值:
  - code_start, code_end, base_addr, vm_addr
这是最可靠的方式，不依赖任何自动发现启发式。

方案 B: 修改自动发现启发式

static_deobfuscate.py → static_vmctx():
  1. 段名查找: '.vmp' → 改为目标保护器的段名
  2. 最大函数: 可能需要按其他特征（如 xref 数量）查找
  3. 跳转表: 正则匹配需适配 IDA 的输出格式
  4. 字节码范围: 需根据具体布局调整

TraceAnalysis.py → dynamic_vm_values():
  1. push 频率统计: 可改为"特定模式"频率统计
  2. off_XXX 解析: 适配不同的间接寻址格式
```

### 2.6 变体六：特殊的虚拟指令

**问题**：VM 实现了当前 15 种之外的虚拟指令。

**修改方案**：

```
步骤 1: 在 PseudoInstruction.py 中添加新类型

  # 新增指令类型
  XOR_T = 'xor_T'       # 异或
  SUB_T = 'sub_T'       # 减法
  SWAP_T = 'swap_T'     # 栈顶交换
  DUP_T = 'dup_T'       # 栈顶复制

  # 新增 I/O 模式（如果需要）
  IN0_OUT1 = 'in0_out1'  # 0输入1输出（如常量压栈）

步骤 2: 在 VmInstruction.py 中添加识别方法

  def is_xor(self):
      """识别 vxor: xor reg1, reg2（非立即数）"""
      for inst in self.Instructions:
          if inst.is_xor():  # 需在 Instruction.py 中添加
              ...

步骤 3: 在 get_pseudo_code() 中注册新模式

  def get_pseudo_code(self):
      ...
      if self.is_xor():     # 在适当优先级位置插入
          return
      ...

步骤 4: 在 PseudoInstruction.make_pop_push_rep() 中添加展开规则

  按 I/O 模式添加展开模板（参考现有的 IN2_OUT2 等）
```

## 3. 实际适配工作流程

面对一个新的 VM 保护方案，建议按以下流程操作：

### Phase 1: 侦察（不修改代码）

```
1. 在 IDA 中加载受保护的二进制文件

2. 识别 VM 基础结构
   ├─ VM 入口地址（通常是 call 目标）
   ├─ dispatch 循环位置（特征：间接跳转/call）
   ├─ 跳转表位置和结构
   ├─ 字节码区域范围
   └─ handler 的终止方式

3. 选取 2-3 个简单的 handler 手动分析
   ├─ 确定寄存器角色（哪个是 VPC？哪个是 VSP？）
   ├─ 确定栈操作方式（sub/add？lea？push/pop？）
   ├─ 确定 catch 机制（如何读取立即数？）
   └─ 确定操作码编码（单字节？多字节？）

4. 记录发现:
   VM_PC = ?          (当前假设: ESI/RSI)
   VM_SP = ?          (当前假设: EBP/RBP)
   VM_SCRATCH = ?     (当前假设: EDI)
   OPCODE_SIZE = ?    (当前假设: 1 字节)
   TABLE_TYPE = ?     (当前假设: 线性 Dword/Qword 数组)
   HANDLER_END = ?    (当前假设: jmp dispatch)
   STACK_GROW = ?     (当前假设: sub = push, add = pop)
```

### Phase 2: 动态分析适配

```
优先适配动态分析路径，因为:
  - trace 的采集（IDADebugger）不依赖 VM 假设
  - TraceOptimizations 的大部分优化是通用的
  - 可以先获取 trace 再进行离线分析

需要修改:
  1. TraceAnalysis.py 中的 VM 定位启发式
     (如果自动定位失败，手动通过 Settings 设置 VMContext)

  2. follow_virt_reg() 中的寄存器过滤列表
     将 ['esi','edi','ebp',...] 改为目标 VM 的基础设施寄存器

  3. TraceOptimizations.py 中的窥孔优化
     确保不会误删目标 VM 的关键指令
```

### Phase 3: 静态分析适配

```
静态分析需要更多修改，建议按层次进行:

Layer 1: Instruction.py（最底层）
  ├─ 修改寄存器判断方法
  ├─ 如需要，添加新的指令类型判断
  └─ 测试: 确保单条 handler 指令能正确查询

Layer 2: VmInstruction.py（模式匹配）
  ├─ 修改现有模式的匹配条件
  ├─ 添加新的虚拟指令识别
  └─ 测试: 确保 2-3 个已知 handler 能正确识别

Layer 3: static_deobfuscate.py（编排层）
  ├─ 修改字节码遍历逻辑
  ├─ 修改跳转表查找
  ├─ 修改 handler 终止条件
  └─ 测试: 确保能遍历完整字节码区域

Layer 4: PseudoInstruction + Optimize（优化层）
  ├─ 添加新的指令类型和展开规则
  ├─ 验证优化管线的正确性
  └─ 测试: 确保优化后的伪指令语义正确
```

### Phase 4: 验证

```
使用 Example/ 目录下的示例验证:
  1. 先用原始代码跑一遍示例，确认基线正确
  2. 修改后跑新的目标二进制
  3. 对比结果:
     - 静态: IDA 注释中的伪指令是否语义正确？
     - 动态: grading 是否正确高亮了关键指令？
     - CFG: 控制流图是否合理？
```

## 4. 架构改进建议

如果需要频繁适配不同 VM，建议以下架构改进：

### 4.1 寄存器角色参数化

```python
# lib/StartVal.py 中添加
class VMConfig(object):
    """VM 结构配置，替代硬编码假设"""
    def __init__(self):
        self.vpc_reg = 'ESI'      # VM 指令指针寄存器
        self.vsp_reg = 'EBP'      # VM 栈指针寄存器
        self.scratch_reg = 'EDI'  # VM 暂存区寄存器
        self.opcode_size = 1      # 操作码字节数
        self.table_entry_size = 4 # 跳转表项字节数（32位=4, 64位=8）
        self.stack_grows_down = True  # True=sub是push, False=add是push
        self.handler_end = 'jmp'  # handler 终止方式: 'jmp'/'call'/'fallthrough'
        self.vm_noise_regs = ['esi','edi','ebp','rsi','rdi','rbp']  # 过滤列表
```

### 4.2 Instruction 方法参数化

```python
# 当前（硬编码）:
def is_catch_instr(self):
    if 'ESI' in reg_name or 'RSI' in reg_name:
        return True

# 改进（参数化）:
def is_catch_instr(self, vpc_reg=None):
    if vpc_reg is None:
        vpc_reg = SV.vm_config.vpc_reg
    vpc_64 = vpc_reg.replace('E', 'R')
    if vpc_reg in reg_name or vpc_64 in reg_name:
        return True
```

### 4.3 模式匹配插件化

```python
# 将 VmInstruction 的模式匹配改为可注册的插件

class VmPatternRegistry(object):
    def __init__(self):
        self.patterns = []

    def register(self, name, matcher_func, priority=50):
        self.patterns.append((priority, name, matcher_func))
        self.patterns.sort(key=lambda x: x[0])

    def match(self, vm_inst):
        for priority, name, matcher in self.patterns:
            result = matcher(vm_inst)
            if result is not None:
                return result
        return None

# 使用:
registry = VmPatternRegistry()
registry.register('vpush', match_vpush, priority=10)
registry.register('vpop', match_vpop, priority=20)
registry.register('vadd', match_vadd, priority=30)
# 用户可以 register 自定义模式
```

### 4.4 字节码遍历策略化

```python
# 将字节码遍历逻辑从 first_deobfuscate 中抽取为策略

class BytecodeWalker(object):
    """字节码遍历策略基类"""
    def read_opcode(self, addr):
        raise NotImplementedError
    def calc_handler(self, opcode, base):
        raise NotImplementedError
    def read_catch(self, addr, handler_insts):
        raise NotImplementedError

class StandardWalker(BytecodeWalker):
    """当前的标准策略: 单字节opcode + 线性跳转表"""
    def read_opcode(self, addr):
        return Byte(addr), 1

    def calc_handler(self, opcode, base):
        return Dword(opcode * 4 + base)

class CustomWalker(BytecodeWalker):
    """用户自定义策略示例"""
    def read_opcode(self, addr):
        return Word(addr), 2  # 双字节操作码
    ...
```

## 5. 快速参考：修改检查清单

面对新 VM 时，按此清单逐项确认：

- [ ] **寄存器角色**：VPC/VSP/暂存区分别是哪个寄存器？
  - 修改 `Instruction.py` 的 6+ 个寄存器判断方法
  - 修改 `TraceAnalysis.py` 的过滤列表
- [ ] **操作码编码**：单字节/多字节/变长？
  - 修改 `static_deobfuscate.py:first_deobfuscate()` 的读取逻辑
  - 修改 `deobfuscate_all()` 的遍历范围
- [ ] **跳转表结构**：线性数组/哈希/switch-case？
  - 修改 `calc_code_addr()`
  - 修改 `static_vmctx()` 的自动发现
- [ ] **Handler 终止**：jmp/call/fall-through/ret？
  - 修改 `get_instruction_list()` 的终止条件
- [ ] **栈操作方式**：sub-add/add-sub/lea/push-pop？
  - 修改 `Instruction.py` 的栈操作判断
  - 可能需要修改 `VmInstruction.py` 的 `is_push`/`is_pop`
- [ ] **VM 栈帧建立**：`mov ebp,esp`/`enter`/`lea`/其他？
  - 修改 `is_mov_basep_stackp()`
  - 修改 `get_start_push()` 的终止条件
- [ ] **VM 定位**：.vmp 段名/特征函数/其他？
  - 修改 `static_vmctx()`
  - 或直接通过 Settings 手动设置
- [ ] **虚拟指令集**：是否有当前 15 种以外的指令？
  - 在 `VmInstruction.py` 中添加新模式
  - 在 `PseudoInstruction.py` 中添加类型和展开规则
- [ ] **Catch 机制**：通过 ESI 读取/其他方式？
  - 修改 `is_catch_instr()` 的判断条件
  - 修改 `first_deobfuscate()` 中 catch 值的读取

## 6. 附录：不同 VM 保护方案特征速查

| 特征 | VMProtect (类) | Themida (类) | Code Virtualizer (类) |
|------|---------------|-------------|----------------------|
| VPC 寄存器 | ESI/RSI | 可变 | 可变 |
| VSP 寄存器 | EBP/RBP | 可变 | EBP/RBP |
| 操作码 | 单字节 | 双字节常见 | 单字节 |
| 跳转表 | 线性数组 | 哈希/加密 | 线性数组 |
| Handler 终止 | jmp dispatch | jmp/条件分支 | jmp dispatch |
| 指令集 | ~15 种 | 20-50 种 | ~20 种 |
| 特殊技巧 | NOR 替代逻辑运算 | 多层 VM 嵌套 | handler 变异 |
| 反分析 | 段名混淆 | 控制流平坦化 | handler 加密 |

> 注意：以上信息为通用参考，不同版本和配置可能差异很大。始终以实际逆向分析为准。

## 7. 实战案例：TVM 架构分析与适配方案

以下是对一个实际 VM 保护方案的逆向分析结果，展示如何将适配指南中的方法论应用于真实场景。

### 7.1 目标函数

- **函数地址**: `0x14003EF70`
- **保护方案**: TVM（自定义虚拟机保护）
- **架构**: x86-64
- **分析方法**: IDA Pro CFG 导出 + SVG 图形分析

### 7.2 VM 入口序列分析

```
0x14003EF70: jmp 0x1404463C2             ← VM入口（jmp 转发到 VM 初始化）

=== VM 初始化 (0x1404463C2, 19条指令) ===

0x1404463C2: lea rsp, [rsp - 0x290]     ← 分配 0x290 字节的 VM 上下文空间
0x1404463CA: mov [rsp + 0x10], rbp      ← 保存原始 rbp
0x1404463CF: mov rbp, rsp               ← ★ rbp = VM 上下文基址
0x1404463D2: pushfq                     ← 保存 flags
0x1404463D3: pop [rbp]                  ← flags → [rbp+0x00]
0x1404463D6: mov [rbp + 0x78], r14      ← 保存 r14

--- 混淆的寄存器保存（not+xchg 模式）---
0x1404463DA: not r11                    ┐
0x1404463DD: xchg rdx, r11             │ 等价于保存 rdx
0x1404463E0: mov [rbp + 0x30], r11     │ [rbp+0x30] = 原始 rdx
0x1404463E4: not rdx                   │ 恢复 rdx
0x1404463E7: xchg rdx, r11            ┘

0x1404463EA: not rax                   ┐
0x1404463ED: xchg r9, rax              │ 等价于保存 rax
0x1404463EF: mov [rbp + 0x50], rax     │ [rbp+0x50] = 原始 rax
0x1404463F3: not r9                    ┘ r9 = 原始 rax

--- 计算下一个 handler 地址（混淆的 lea）---
0x1404463F6: push rdx
0x1404463F7: lea rdx, [rip + 0x6716164B]
0x1404463FE: lea rdx, [rdx - 0x67160F5C]  ← rdx = 相对偏移计算
0x140446405: jmp rdx                       ← 跳转到下一个基本块
```

### 7.3 VM 上下文布局

```
RBP → VM Context (0x290 bytes)
┌────────────────────────────────────────┐
│ [rbp + 0x00]  = RFLAGS               │
│ [rbp + 0x08]  = RCX                  │
│ [rbp + 0x10]  = 原始 RBP（保存的调用者）│
│ [rbp + 0x18]  = RBX                  │
│ [rbp + 0x20]  = R10                  │
│ [rbp + 0x28]  = RDI                  │
│ [rbp + 0x30]  = RDX （via not+xchg） │
│ [rbp + 0x38]  = RSI                  │
│ [rbp + 0x40]  = RSP（原始栈指针）      │
│ [rbp + 0x48]  = R9 / 临时            │
│ [rbp + 0x50]  = RAX （via not+xchg） │
│ [rbp + 0x58]  = R9 / 临时            │
│ [rbp + 0x60]  = ★ VPC（字节码指针）  │  ← 关键！
│ [rbp + 0x68]  = R12                  │
│ [rbp + 0x70]  = R13                  │
│ [rbp + 0x78]  = R14                  │
│ [rbp + 0x80]  = R15                  │
│ [rbp + 0x88+] = VM 操作栈空间         │
└────────────────────────────────────────┘
```

### 7.4 Handler 分发机制

此 VM **没有集中的 dispatch 循环**。每个 handler 自行完成：

```
1. 加载 VPC:     mov r9, [rbp + 0x60]
2. 读取操作码:   mov r8w, word ptr [r9]        ← ★ 2字节操作码
3. 解码操作码:   复杂的 MBA 运算（xor/and/or/not 配合内存常量）
4. 推进 VPC:     add r9, 2 (或更多，取决于是否有 catch)
                 通过混淆计算写回 [rbp+0x60]
5. 计算目标:     lea + movsxd + 混淆运算 → handler 相对偏移
                 lea r9, [rip + base_table]
                 add r9, r8(offset)            ← 查跳转表
6. 跳转:         jmp rdx/r8/r9/r11/rax/rcx     ← 目标寄存器不固定
```

特征码：每个 handler 末尾都能看到 `movsxd` + `lea [rip+...]` + `add` + 混淆运算 + `jmp reg` 的模式。

### 7.5 MBA 混淆分析

Handler 中大量使用 Mixed Boolean-Arithmetic (MBA) 混淆，典型模式：

```
=== 恒等变换（混淆的 mov）===
原始语义: mov dst, src
混淆实现:
  mov dst, src
  and dst, src       ← a & a = a（冗余）
  and dst, 0xMASK
  mov tmp, dst
  and tmp, [rip+C1]
  xor tmp, [rip+C2]
  or dst, tmp        ← 恒等变换链
  xor dst, src

=== NOR 运算 ===
原始语义: result = val
混淆实现:
  not a
  xor a, [rip+C1]
  xor a, [rip+C2]  ← C1 xor C2 = 0，两次 xor 抵消
  not a             ← 两次 not 抵消
  or a, b
  not a

=== 混淆的地址计算 ===
lea r9, [rip + LARGE_CONST]
movsxd r8, r8d
add r9, r8
not rcx; add r9, r8; not r9
or rcx, r9; not rcx; or rdx, rcx
jmp rdx               ← 经过混淆的间接跳转
```

### 7.6 与 VMAttack 假设的对比

| 维度 | VMAttack 假设 | TVM 实际 | 差异程度 |
|------|-------------|---------|:---:|
| VPC 存储 | ESI/RSI 寄存器 | `[rbp+0x60]` 内存 | **极大** |
| VPC 加载 | 直接使用 ESI | `mov r9, [rbp+0x60]` 间接 | **极大** |
| 操作码宽度 | 1 字节 | 2 字节 (word) | **大** |
| 跳转表 | `Dword(opcode*4+base)` 直接查表 | 经 MBA 混淆的相对偏移计算 | **极大** |
| Handler 终止 | `jmp dispatch`（固定目标） | `jmp reg`（每次不同寄存器） | **大** |
| Dispatch 模式 | 集中式循环 | 每个 handler 自带 dispatch | **极大** |
| 寄存器保存 | 直接 push/mov | `not+xchg+mov` 混淆 | **中** |
| 栈操作 | `sub ebp`=push, `add ebp`=pop | 待进一步分析 | **待定** |
| RBP 角色 | VM 栈顶指针 | VM 上下文结构体基址 | **极大** |
| 混淆层 | 无 | 大量 MBA 混淆 | **新增需求** |

### 7.7 适配方案

#### 方案 A：优先动态分析（推荐）

动态分析路径的适配成本最低，因为 trace 采集不依赖 VM 结构假设：

```
1. 不需要修改的部分:
   - IDADebugger.py（trace 采集是通用的）
   - TraceRepresentation.py（数据结构通用）
   - DebuggerHandler.py（trace I/O 通用）

2. 需要小改的部分:
   TraceOptimizations.py:
     - 窥孔优化中 MBA 混淆指令会被保留（需要排除）
     - 新增 MBA 化简优化步骤

   TraceAnalysis.py:
     - find_vm_addr(): 此 VM 可能无 .vmp 段名 → 手动设置
     - follow_virt_reg(): 过滤列表需要扩展
       当前: ['esi','edi','ebp','rsi','rdi','rbp']
       应改为包含所有 VM 基础设施操作

3. 需要手动设置:
   通过 Settings 窗口设置 VMContext:
     - vm_addr = 0x1404463C2
     - code_start, code_end = 待确定（字节码区域）
     - base_addr = 待确定（handler 偏移表基址）

4. 建议的分析流程:
   ① 在 IDA 中设断点在 VM 入口
   ② 生成完整 trace
   ③ 使用常量传播（会揭示实际的寄存器值）
   ④ 使用 grading_automaton（MBA 噪声会自动降分）
   ⑤ 手动检查高分行，还原语义
```

#### 方案 B：静态分析适配（工作量大）

如果需要完整的静态分析能力：

```
Layer 0: 新增 MBA 化简器（最重要的前置步骤）
  lib/MBASimplifier.py:
    - 识别 not+xchg 寄存器保存模式 → 简化为 mov
    - 识别 xor [rip+C1]; xor [rip+C2] 对消 → 删除
    - 识别 not; xor; not 恒等链 → 删除
    - 识别 and a,a / or a,a 冗余 → 删除
    - 处理 [rip+offset] 常量引用 → 用实际值替换

Layer 1: 修改 Instruction.py
  - is_catch_instr(): 
      识别 "mov reg, word ptr [LOADED_VPC]" 模式
      LOADED_VPC 是从 [rbp+0x60] 加载到某 GPR 的值
  - is_vinst(): 
      识别涉及 [rbp+0x60] 或已知 VPC 寄存器的指令
  - is_write_stack() / is_read_stack(): 
      识别 [rbp+0x88+] 范围的栈操作（非上下文区域）
  - is_sub_basepointer() / is_add_basepointer():
      此 VM 可能不使用 sub/add rbp（rbp 是固定的上下文指针）
      需要分析 VM 栈指针的实际操作方式

Layer 2: 修改 static_deobfuscate.py
  - calc_code_addr(): 
      需要模拟 MBA 混淆的地址计算
      或建立 opcode → handler 映射表（通过穷举或 trace）
  - get_instruction_list():
      终止条件改为检测 "lea [rip+base] + movsxd + jmp reg" 模式
  - first_deobfuscate():
      操作码读取改为 Word(addr)（2字节）
      catch 长度计算需调整

Layer 3: 修改 VmInstruction.py
  - 所有模式匹配需要在 MBA 化简后的指令上进行
  - 可能需要新增模式来适应不同的 handler 实现
```

#### 方案 C：混合方案（最实用）

```
动态采集 → 静态辅助:

1. 用动态 trace 建立 handler 映射表
   - 在 dispatch 处记录: (VPC值, 操作码, handler入口)
   - 自动发现所有使用到的 handler

2. 用 trace 驱动 MBA 化简
   - 对每个 handler 用 trace 中的实际值验证 MBA 化简结果
   - 确保化简正确后再做模式匹配

3. 用静态分析深化理解
   - 对化简后的 handler 做 VmInstruction 模式匹配
   - 结果交叉验证

这种方案利用了动态分析的准确性和静态分析的完整性。
```

### 7.8 此 VM 的独特挑战总结

1. **内存化 VPC**: 字节码指针不在固定寄存器中，而是存在 VM 上下文的 `[rbp+0x60]` 位置，每次 handler 需要先加载
2. **MBA 混淆密度极高**: 每个 handler 约 60-150 条指令，其中超过 70% 是混淆噪声
3. **分散式 dispatch**: 无集中分发循环，每个 handler 自行完成 fetch-decode-dispatch
4. **操作码加密**: 从字节码读取的 word 经过多层 xor/and/or 变换后才能得到真实的 handler 索引
5. **跳转寄存器不固定**: 不同 handler 末尾的 `jmp` 使用不同寄存器（rdx/r8/r9/r11/rax/rcx）

这些特征表明这是一个**高度定制的 VM 保护方案**，比标准 VMProtect 更难分析。适配 VMAttack 需要显著的工作量，建议以动态分析为主要手段。
