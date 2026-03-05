"""
批量扫描模块
支持多目标批量扫描
"""

import asyncio
import os
from typing import List, Dict, Optional
from pathlib import Path
from datetime import datetime

from core.base import BaseModule, ScanResult, Severity, ResultType
from core.scanner import Scanner, ScanReport
from core.logger import Logger, logger
from core.database import db


class BatchScanner:
    """
    批量扫描器
    支持从文件读取目标，批量执行扫描
    """
    
    def __init__(self, config=None, custom_logger=None):
        self.config = config
        self.logger = custom_logger or logger
        self.scanner = Scanner(config, custom_logger)
        self.results: List[ScanReport] = []
    
    def load_targets_from_file(self, filepath: str) -> List[str]:
        """
        从文件加载目标列表
        
        Args:
            filepath: 目标文件路径，每行一个目标
            
        Returns:
            目标列表
        """
        targets = []
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # 跳过注释和空行
                    if line and not line.startswith('#'):
                        targets.append(line)
        except FileNotFoundError:
            self.logger.error(f"目标文件不存在: {filepath}")
        
        return targets
    
    def load_targets_from_nmap(self, filepath: str) -> List[str]:
        """
        从Nmap输出文件加载目标
        
        Args:
            filepath: Nmap输出文件路径
            
        Returns:
            目标列表
        """
        targets = []
        import re
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # 提取开放HTTP/HTTPS端口的主机
                # 匹配格式: Nmap scan report for xxx (ip)
                #          PORT    STATE SERVICE
                #          80/tcp  open  http
                
                host_pattern = r'Nmap scan report for .*?(\d+\.\d+\.\d+\.\d+)'
                port_pattern = r'(\d+)/(tcp|udp)\s+open\s+(http|https|http-proxy|http-alt)'
                
                lines = content.split('\n')
                current_host = None
                
                for line in lines:
                    host_match = re.search(host_pattern, line)
                    if host_match:
                        current_host = host_match.group(1)
                    
                    port_match = re.search(port_pattern, line)
                    if port_match and current_host:
                        port = port_match.group(1)
                        service = port_match.group(3)
                        
                        scheme = 'https' if port == '443' or 'https' in service else 'http'
                        target = f"{scheme}://{current_host}:{port}"
                        targets.append(target)
                        
        except FileNotFoundError:
            self.logger.error(f"Nmap文件不存在: {filepath}")
        
        return list(set(targets))
    
    async def scan_targets(
        self,
        targets: List[str],
        modules: List[str] = None,
        concurrency: int = 3,
        save_db: bool = True
    ) -> List[ScanReport]:
        """
        批量扫描多个目标
        
        Args:
            targets: 目标列表
            modules: 要运行的模块
            concurrency: 并发扫描数
            save_db: 是否保存到数据库
            
        Returns:
            扫描报告列表
        """
        self.logger.print_banner()
        self.logger.info(f"批量扫描: {len(targets)} 个目标")
        self.logger.info(f"并发数: {concurrency}")
        
        semaphore = asyncio.Semaphore(concurrency)
        self.results = []
        
        async def scan_single(target: str) -> Optional[ScanReport]:
            async with semaphore:
                try:
                    self.logger.info(f"\n{'='*50}")
                    self.logger.info(f"扫描目标: {target}")
                    self.logger.info(f"{'='*50}")
                    
                    report = await self.scanner.scan(target, modules)
                    
                    if save_db:
                        # 保存到数据库
                        scan_id = db.create_scan(target, modules or [])
                        for result in report.results:
                            db.add_finding(scan_id, result.to_dict())
                        
                        severity_dist = {}
                        for r in report.results:
                            sev = r.severity.value
                            severity_dist[sev] = severity_dist.get(sev, 0) + 1
                        
                        db.update_scan(
                            scan_id,
                            status="completed",
                            total_findings=len(report.results),
                            severity_distribution=severity_dist
                        )
                    
                    return report
                    
                except Exception as e:
                    self.logger.error(f"扫描失败 {target}: {e}")
                    return None
        
        # 创建任务
        tasks = [scan_single(target) for target in targets]
        
        # 执行
        completed = 0
        total = len(tasks)
        
        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed += 1
            
            if result:
                self.results.append(result)
            
            self.logger.info(f"\n进度: {completed}/{total}")
        
        # 打印总结
        self._print_summary()
        
        return self.results
    
    async def scan_from_file(
        self,
        filepath: str,
        modules: List[str] = None,
        concurrency: int = 3,
        save_db: bool = True
    ) -> List[ScanReport]:
        """
        从文件读取目标并批量扫描
        
        Args:
            filepath: 目标文件路径
            modules: 要运行的模块
            concurrency: 并发扫描数
            save_db: 是否保存到数据库
            
        Returns:
            扫描报告列表
        """
        targets = self.load_targets_from_file(filepath)
        
        if not targets:
            self.logger.error("未找到有效目标")
            return []
        
        return await self.scan_targets(targets, modules, concurrency, save_db)
    
    def _print_summary(self) -> None:
        """打印批量扫描总结"""
        self.logger.info("\n" + "=" * 60)
        self.logger.highlight("批量扫描完成!")
        self.logger.info("=" * 60)
        
        total_findings = 0
        severity_count = {}
        
        for report in self.results:
            total_findings += len(report.results)
            for result in report.results:
                sev = result.severity.value
                severity_count[sev] = severity_count.get(sev, 0) + 1
        
        self.logger.info(f"扫描目标: {len(self.results)} 个")
        self.logger.info(f"总发现数: {total_findings}")
        
        if severity_count:
            self.logger.info("\n严重程度分布:")
            for sev, count in sorted(severity_count.items()):
                self.logger.info(f"  {sev.upper()}: {count}")
    
    def save_results(self, output_dir: str = "outputs/batch") -> None:
        """
        保存批量扫描结果
        
        Args:
            output_dir: 输出目录
        """
        from modules.report.generator import ReportGenerator
        
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        generator = ReportGenerator(self.config, self.logger)
        
        for report in self.results:
            # 生成安全的文件名
            safe_name = report.target.replace('://', '_').replace('/', '_').replace(':', '_')
            output_path = os.path.join(output_dir, f"{safe_name}.html")
            generator.generate(report, output_path, 'html')
        
        self.logger.success(f"结果已保存到: {output_dir}")
    
    def export_summary(self, output_path: str = "outputs/batch_summary.csv") -> None:
        """
        导出扫描摘要为CSV
        
        Args:
            output_path: 输出文件路径
        """
        import csv
        
        Path(os.path.dirname(output_path)).mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Target', 'Duration', 'Total Findings', 'Critical', 'High', 'Medium', 'Low', 'Info'])
            
            for report in self.results:
                severity = {}
                for r in report.results:
                    sev = r.severity.value
                    severity[sev] = severity.get(sev, 0) + 1
                
                writer.writerow([
                    report.target,
                    f"{report.duration:.2f}s",
                    len(report.results),
                    severity.get('critical', 0),
                    severity.get('high', 0),
                    severity.get('medium', 0),
                    severity.get('low', 0),
                    severity.get('info', 0)
                ])
        
        self.logger.success(f"摘要已导出: {output_path}")


# 便捷函数
async def batch_scan(
    targets: List[str],
    modules: List[str] = None,
    concurrency: int = 3
) -> List[ScanReport]:
    """
    批量扫描便捷函数
    
    Args:
        targets: 目标列表
        modules: 要运行的模块
        concurrency: 并发数
        
    Returns:
        扫描报告列表
    """
    scanner = BatchScanner()
    return await scanner.scan_targets(targets, modules, concurrency)
