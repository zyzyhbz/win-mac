"""
日志管理模块
支持控制台输出和文件日志，带颜色和格式化
"""

import os
import logging
import sys
from datetime import datetime
from typing import Optional
from pathlib import Path
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme


# 自定义主题
custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "red bold",
    "critical": "red bold reverse",
    "success": "green",
    "highlight": "magenta",
    "url": "blue underline",
})


class Logger:
    """
    日志管理器
    支持控制台彩色输出和文件日志记录
    """
    
    _instance: Optional['Logger'] = None
    _initialized: bool = False
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(
        self,
        name: str = "PySecScanner",
        log_dir: str = "logs",
        log_level: int = logging.INFO,
        console_output: bool = True,
        file_output: bool = True
    ):
        if self._initialized:
            return
        
        self.name = name
        self.log_dir = log_dir
        self.log_level = log_level
        self.console_output = console_output
        self.file_output = file_output
        
        # 创建日志目录
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        
        # 创建logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(log_level)
        self.logger.handlers.clear()
        
        # Rich Console
        self.console = Console(theme=custom_theme)
        
        # 添加处理器
        if console_output:
            self._add_console_handler()
        
        if file_output:
            self._add_file_handler()
        
        self._initialized = True
    
    def _add_console_handler(self) -> None:
        """添加控制台处理器"""
        handler = RichHandler(
            console=self.console,
            show_time=True,
            show_path=False,
            rich_tracebacks=True,
            tracebacks_show_locals=True
        )
        handler.setLevel(self.log_level)
        formatter = logging.Formatter("%(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def _add_file_handler(self) -> None:
        """添加文件处理器"""
        log_file = os.path.join(
            self.log_dir,
            f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        handler = logging.FileHandler(log_file, encoding='utf-8')
        handler.setLevel(self.log_level)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def info(self, message: str) -> None:
        """记录信息级别日志"""
        self.logger.info(message)
    
    def warning(self, message: str) -> None:
        """记录警告级别日志"""
        self.logger.warning(message)
    
    def error(self, message: str) -> None:
        """记录错误级别日志"""
        self.logger.error(message)
    
    def critical(self, message: str) -> None:
        """记录严重错误级别日志"""
        self.logger.critical(message)
    
    def debug(self, message: str) -> None:
        """记录调试级别日志"""
        self.logger.debug(message)
    
    def success(self, message: str) -> None:
        """记录成功信息"""
        self.console.print(f"[✓] {message}", style="success")
    
    def highlight(self, message: str) -> None:
        """高亮显示重要信息"""
        self.console.print(f"[!] {message}", style="highlight")
    
    def url(self, message: str) -> None:
        """显示URL"""
        self.console.print(f"    → {message}", style="url")
    
    def print_banner(self) -> None:
        """打印程序Banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗ ██╗   ██╗███████╗██████╗  ██████╗ ███████╗         ║
║   ██╔══██╗██║   ██║██╔════╝██╔══██╗██╔═══██╗██╔════╝         ║
║   ██████╔╝██║   ██║███████╗██████╔╝██║   ██║███████╗         ║
║   ██╔══██╗██║   ██║╚════██║██╔══██╗██║   ██║╚════██║         ║
║   ██████╔╝╚██████╔╝███████║██████╔╝╚██████╔╝███████║         ║
║   ╚═════╝  ╚═════╝ ╚══════╝╚═════╝  ╚═════╝ ╚══════╝         ║
║                                                               ║
║           信息搜集与漏洞扫描工具 v1.0.0                       ║
║           Security Scanner for Learning & Testing             ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
        """
        self.console.print(banner, style="cyan")
    
    def print_target(self, target: str) -> None:
        """显示扫描目标"""
        self.console.print(f"\n[+] 目标: {target}", style="info")
    
    def print_module(self, module_name: str) -> None:
        """显示当前运行的模块"""
        self.console.print(f"\n{'='*60}", style="dim")
        self.console.print(f"  模块: {module_name}", style="cyan bold")
        self.console.print(f"{'='*60}", style="dim")
    
    def print_result(self, title: str, items: list) -> None:
        """格式化打印结果列表"""
        self.console.print(f"\n[+] {title}:", style="success")
        for item in items:
            # 使用普通字符，避免 Windows GBK 控制台编码问题
            self.console.print(f"    - {item}")
    
    def print_progress(self, current: int, total: int, description: str = "") -> None:
        """显示进度"""
        percentage = (current / total) * 100 if total > 0 else 0
        bar_length = 30
        filled = int(bar_length * current / total) if total > 0 else 0
        # 使用 ASCII 字符，避免在 Windows GBK 控制台下出现编码问题
        bar = '#' * filled + '-' * (bar_length - filled)
        self.console.print(
            f"\r    [{bar}] {percentage:.1f}% ({current}/{total}) {description}",
            end=""
        )


# 全局日志实例
logger = Logger()
