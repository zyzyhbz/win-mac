"""
核心扫描器
协调各模块执行扫描任务
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Type
from dataclasses import dataclass, field
from pathlib import Path

from core.config import Config
from core.logger import Logger, logger
from core.base import BaseModule, ScanResult, Severity


@dataclass
class ScanTask:
    """扫描任务"""
    target: str
    modules: List[str] = field(default_factory=list)
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanReport:
    """扫描报告"""
    target: str
    start_time: float
    end_time: float
    results: List[ScanResult] = field(default_factory=list)
    module_stats: List[Dict[str, Any]] = field(default_factory=list)
    
    @property
    def duration(self) -> float:
        return self.end_time - self.start_time
    
    def get_summary(self) -> Dict[str, Any]:
        """获取扫描摘要"""
        severity_count = {}
        for result in self.results:
            sev = result.severity.value
            severity_count[sev] = severity_count.get(sev, 0) + 1
        
        return {
            'target': self.target,
            'duration': self.duration,
            'total_findings': len(self.results),
            'severity_distribution': severity_count
        }


class Scanner:
    """
    主扫描器类
    负责协调各模块执行扫描任务
    """
    
    def __init__(
        self,
        config: Optional[Config] = None,
        custom_logger: Optional[Logger] = None
    ):
        self.config = config or Config()
        self.logger = custom_logger or logger
        self._modules: Dict[str, Type[BaseModule]] = {}
        self._results: List[ScanResult] = []
        
        # 自动注册模块
        self._auto_register_modules()
    
    def _auto_register_modules(self) -> None:
        """自动注册所有可用模块"""
        # 信息搜集模块
        try:
            from modules.recon.port_scanner import PortScanner
            self.register_module('port_scan', PortScanner)
        except ImportError:
            pass
        
        try:
            from modules.recon.subdomain_enum import SubdomainEnumerator
            self.register_module('subdomain', SubdomainEnumerator)
        except ImportError:
            pass
        
        try:
            from modules.recon.dir_scanner import DirScanner
            self.register_module('dir_scan', DirScanner)
        except ImportError:
            pass
        
        # 漏洞扫描模块
        try:
            from modules.vulnscan.sql_injection import SQLInjectionScanner
            self.register_module('sqli', SQLInjectionScanner)
        except ImportError:
            pass
        
        try:
            from modules.vulnscan.xss_scanner import XSSScanner
            self.register_module('xss', XSSScanner)
        except ImportError:
            pass
        
        try:
            from modules.vulnscan.sensitive_info import SensitiveInfoScanner
            self.register_module('sensitive', SensitiveInfoScanner)
        except ImportError:
            pass
    
    def register_module(self, name: str, module_class: Type[BaseModule]) -> None:
        """
        注册扫描模块
        
        Args:
            name: 模块名称
            module_class: 模块类
        """
        self._modules[name] = module_class
        self.logger.debug(f"注册模块: {name} -> {module_class.__name__}")
    
    def get_available_modules(self) -> List[str]:
        """获取所有可用模块列表"""
        return list(self._modules.keys())
    
    def get_module_info(self, name: str) -> Optional[Dict[str, str]]:
        """获取模块信息"""
        if name in self._modules:
            module_class = self._modules[name]
            return {
                'name': module_class.name,
                'description': module_class.description,
                'version': module_class.version,
                'author': module_class.author
            }
        return None
    
    async def run_module(self, module_name: str, target: str) -> List[ScanResult]:
        """
        运行单个模块
        
        Args:
            module_name: 模块名称
            target: 扫描目标
            
        Returns:
            扫描结果列表
        """
        if module_name not in self._modules:
            self.logger.error(f"模块不存在: {module_name}")
            return []
        
        module_class = self._modules[module_name]
        module = module_class(self.config, self.logger)
        
        self.logger.print_module(f"{module.name} v{module.version}")
        self.logger.info(f"描述: {module.description}")
        
        try:
            module.pre_scan(target)
            results = await module.scan(target)
            module.post_scan()
            
            # 记录统计信息
            stats = module.get_stats()
            self.logger.info(
                f"模块完成: {stats['total_results']} 个结果, "
                f"耗时: {stats['duration']:.2f}秒"
            )
            
            return results
            
        except Exception as e:
            self.logger.error(f"模块执行错误 [{module_name}]: {e}")
            return []
    
    async def scan(
        self,
        target: str,
        modules: Optional[List[str]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> ScanReport:
        """
        执行扫描任务
        
        Args:
            target: 扫描目标
            modules: 要运行的模块列表，None表示运行所有模块
            options: 扫描选项
            
        Returns:
            扫描报告
        """
        start_time = time.time()
        options = options or {}
        
        # 打印Banner
        self.logger.print_banner()
        self.logger.print_target(target)
        
        # 确定要运行的模块
        if modules is None:
            modules = self.get_available_modules()
        
        if not modules:
            self.logger.warning("没有可用的扫描模块")
            return ScanReport(
                target=target,
                start_time=start_time,
                end_time=time.time()
            )
        
        self.logger.info(f"将运行 {len(modules)} 个模块: {', '.join(modules)}")
        
        # 执行各模块扫描
        all_results: List[ScanResult] = []
        module_stats: List[Dict[str, Any]] = []
        
        for module_name in modules:
            results = await self.run_module(module_name, target)
            all_results.extend(results)
            
            # 收集模块统计
            if results:
                stats = {
                    'module': module_name,
                    'count': len(results),
                    'severity': {}
                }
                for r in results:
                    sev = r.severity.value
                    stats['severity'][sev] = stats['severity'].get(sev, 0) + 1
                module_stats.append(stats)
        
        end_time = time.time()
        
        # 生成报告
        report = ScanReport(
            target=target,
            start_time=start_time,
            end_time=end_time,
            results=all_results,
            module_stats=module_stats
        )
        
        # 打印摘要
        self._print_summary(report)
        
        return report
    
    def _print_summary(self, report: ScanReport) -> None:
        """打印扫描摘要"""
        summary = report.get_summary()
        
        self.logger.info("\n" + "=" * 60)
        self.logger.highlight("扫描完成!")
        self.logger.info("=" * 60)
        self.logger.info(f"目标: {summary['target']}")
        self.logger.info(f"耗时: {summary['duration']:.2f} 秒")
        self.logger.info(f"发现: {summary['total_findings']} 个结果")
        
        if summary['severity_distribution']:
            self.logger.info("\n严重程度分布:")
            for sev, count in summary['severity_distribution'].items():
                self.logger.info(f"  {sev.upper()}: {count}")
    
    def save_results(self, report: ScanReport, output_path: str, format: str = 'json') -> None:
        """保存扫描结果"""
        from modules.report.generator import ReportGenerator
        
        generator = ReportGenerator(self.config, self.logger)
        generator.generate(report, output_path, format)


def create_scanner(config_file: Optional[str] = None) -> Scanner:
    """
    创建扫描器实例的工厂函数
    
    Args:
        config_file: 配置文件路径
        
    Returns:
        Scanner实例
    """
    config = Config(config_file) if config_file else Config()
    return Scanner(config)
