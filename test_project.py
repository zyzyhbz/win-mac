#!/usr/bin/env python3
"""
项目测试脚本
验证各模块是否可以正常导入
"""

import sys
import os

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def test_imports():
    """测试模块导入"""
    print("=" * 60)
    print("PySecScanner 模块导入测试")
    print("=" * 60)
    
    tests = []
    
    # 测试核心模块
    print("\n[1] 测试核心模块...")
    try:
        from core.config import Config
        from core.logger import Logger
        from core.base import BaseModule, ScanResult, Severity
        from core.scanner import Scanner
        print("    ✓ 核心模块导入成功")
        tests.append(("核心模块", True))
    except Exception as e:
        print(f"    ✗ 核心模块导入失败: {e}")
        tests.append(("核心模块", False))
    
    # 测试信息搜集模块
    print("\n[2] 测试信息搜集模块...")
    try:
        from modules.recon.port_scanner import PortScanner
        from modules.recon.subdomain_enum import SubdomainEnumerator
        from modules.recon.dir_scanner import DirScanner
        print("    ✓ 信息搜集模块导入成功")
        tests.append(("信息搜集模块", True))
    except Exception as e:
        print(f"    ✗ 信息搜集模块导入失败: {e}")
        tests.append(("信息搜集模块", False))
    
    # 测试漏洞扫描模块
    print("\n[3] 测试漏洞扫描模块...")
    try:
        from modules.vulnscan.sql_injection import SQLInjectionScanner
        from modules.vulnscan.xss_scanner import XSSScanner
        from modules.vulnscan.sensitive_info import SensitiveInfoScanner
        print("    ✓ 漏洞扫描模块导入成功")
        tests.append(("漏洞扫描模块", True))
    except Exception as e:
        print(f"    ✗ 漏洞扫描模块导入失败: {e}")
        tests.append(("漏洞扫描模块", False))
    
    # 测试报告模块
    print("\n[4] 测试报告生成模块...")
    try:
        from modules.report.generator import ReportGenerator
        print("    ✓ 报告生成模块导入成功")
        tests.append(("报告生成模块", True))
    except Exception as e:
        print(f"    ✗ 报告生成模块导入失败: {e}")
        tests.append(("报告生成模块", False))
    
    # 测试工具模块
    print("\n[5] 测试工具模块...")
    try:
        from utils.helpers import is_valid_ip, is_valid_domain, is_valid_url
        print("    ✓ 工具模块导入成功")
        tests.append(("工具模块", True))
    except Exception as e:
        print(f"    ✗ 工具模块导入失败: {e}")
        tests.append(("工具模块", False))
    
    # 测试配置加载
    print("\n[6] 测试配置加载...")
    try:
        config = Config()
        print(f"    ✓ 配置加载成功")
        print(f"      - 扫描超时: {config.scan.timeout}s")
        print(f"      - 并发数: {config.scan.concurrency}")
        tests.append(("配置加载", True))
    except Exception as e:
        print(f"    ✗ 配置加载失败: {e}")
        tests.append(("配置加载", False))
    
    # 测试扫描器初始化
    print("\n[7] 测试扫描器初始化...")
    try:
        scanner = Scanner()
        modules = scanner.get_available_modules()
        print(f"    ✓ 扫描器初始化成功")
        print(f"      - 可用模块: {', '.join(modules) if modules else '无'}")
        tests.append(("扫描器初始化", True))
    except Exception as e:
        print(f"    ✗ 扫描器初始化失败: {e}")
        tests.append(("扫描器初始化", False))
    
    # 测试工具函数
    print("\n[8] 测试工具函数...")
    try:
        assert is_valid_ip("192.168.1.1") == True
        assert is_valid_ip("999.999.999.999") == False
        assert is_valid_domain("example.com") == True
        assert is_valid_url("http://example.com") == True
        print("    ✓ 工具函数测试通过")
        tests.append(("工具函数", True))
    except Exception as e:
        print(f"    ✗ 工具函数测试失败: {e}")
        tests.append(("工具函数", False))
    
    # 打印总结
    print("\n" + "=" * 60)
    print("测试总结")
    print("=" * 60)
    
    passed = sum(1 for _, status in tests if status)
    total = len(tests)
    
    for name, status in tests:
        symbol = "✓" if status else "✗"
        print(f"  {symbol} {name}")
    
    print(f"\n通过: {passed}/{total}")
    
    if passed == total:
        print("\n🎉 所有测试通过！项目可以正常使用。")
        return 0
    else:
        print("\n⚠️ 部分测试失败，请检查依赖安装。")
        return 1


if __name__ == "__main__":
    exit(test_imports())
