# -*- coding: utf-8 -*-

"""
日志辅助模块。

封装按名称获取 logging.Logger、同时输出到控制台与文件（可选）、统一格式与时间戳。
"""

import logging
import time
import sys

def get_logger(name, console_log = True, file_log = True):
    """
    创建或复用名为 name 的 Logger：级别 DEBUG，可选挂接标准输出与 ``name``.log 文件。

    :param name: 日志器名称，同时用作文件日志文件名前缀
    :param console_log: 是否添加 StreamHandler（stdout）
    :param file_log: 是否添加 FileHandler 写入 name + ".log"
    :return: 配置好的 logging.Logger 实例
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)  # 设置默认日志等级
    formatter = logging.Formatter('%(asctime)s %(levelname)-8s: %(message)s')
    if console_log:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.formatter = formatter
        logger.addHandler(console_handler)
    if file_log:
        # file_handler = logging.FileHandler(name + time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime()) + ".log")
        file_handler = logging.FileHandler(name + ".log")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    return logger