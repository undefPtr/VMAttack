"""开发用远程调试辅助：连接 PyCharm / pydevd。

将仓库内 pycharm-debug.egg 加入 sys.path 后对本机调试端口 settrace，便于在 IDA
插件或脚本中下断点单步。不参与正式发布路径，按需由开发者调用 bp()。
"""

import sys
import os

def bp():
    current_path = os.path.dirname(__file__)
    egg_loc = os.path.join(current_path, "pycharm-debug.egg")
    sys.path.append(egg_loc)
    #print egg_loc
    import pydevd
    pydevd.settrace("localhost", port=12345, stdoutToServer=True, stderrToServer=True)
