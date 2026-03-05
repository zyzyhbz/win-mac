#!/usr/bin/env python3
"""
PySecScanner 启动器
自动检测并启动GUI或命令行模式
"""

import sys
import os

def main():
    """主入口"""
    # 如果有命令行参数，使用命令行模式
    if len(sys.argv) > 1:
        from main import cli
        cli()
    else:
        # 尝试启动GUI
        try:
            from gui.app import main as gui_main
            gui_main()
        except ImportError as e:
            print(f"无法启动GUI: {e}")
            print("请确保已安装 tkinter")
            print("\n使用命令行模式:")
            print("  python main.py --help")
            sys.exit(1)


if __name__ == "__main__":
    main()
