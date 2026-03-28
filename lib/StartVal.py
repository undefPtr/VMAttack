#!/usr/bin/env python
"""
VMAttack 全局配置与启动值模块。

定义汇编目标位宽（32/64 位）等常量，以及反汇编/分析流程使用的全局类型标志，
供各子模块共享统一的初始配置，避免在多处硬编码。
"""
ASSEMBLER_64 = 64
ASSEMBLER_32 = 32

dissassm_type = 0
