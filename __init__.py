"""
PySecScanner - 信息搜集与漏洞扫描工具
一个用于安全测试和学习的综合性扫描框架
"""

__version__ = "1.0.0"
__author__ = "Security Researcher"
__description__ = "信息搜集与漏洞扫描工具"

from core.config import Config
from core.logger import Logger
from core.scanner import Scanner

__all__ = ["Config", "Logger", "Scanner", "__version__"]
