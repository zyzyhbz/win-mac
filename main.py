#!/usr/bin/env python3
"""
PySecScanner - 信息搜集与漏洞扫描工具
命令行入口 v2.0
"""

import asyncio
import click
from typing import Optional, List
from pathlib import Path

from core.config import Config
from core.scanner import Scanner, create_scanner
from core.logger import Logger, logger
from core.database import db


@click.group()
@click.version_option(version='2.0.0', prog_name='PySecScanner')
def cli():
    """
    PySecScanner - 信息搜集与漏洞扫描工具 v2.0
    
    一个用于安全测试和学习的信息搜集与漏洞扫描框架
    
    \b
    快速开始:
      pysec scan http://example.com          # 完整扫描
      pysec portscan 192.168.1.1             # 端口扫描
      pysec batch targets.txt                # 批量扫描
      pysec web                              # 启动Web界面
    """
    pass


@cli.command()
@click.argument('target')
@click.option('--modules', '-m', multiple=True, 
              help='指定模块 (port_scan, subdomain, dir_scan, sqli, xss, ssrf, csrf, xxe, lfi, cmdi, sensitive, poc, fingerprint)')
@click.option('--output', '-o', default='outputs/report.html',
              help='报告输出路径')
@click.option('--format', '-f', 'report_format', default='html',
              type=click.Choice(['html', 'json']),
              help='报告格式')
@click.option('--config', '-c', 'config_file', default=None,
              help='配置文件路径')
@click.option('--timeout', '-t', default=10,
              help='请求超时时间(秒)')
@click.option('--concurrency', default=50,
              help='并发数')
@click.option('--proxy', '-p', default=None,
              help='代理地址 (如 http://127.0.0.1:8080)')
@click.option('--save-db', is_flag=True, default=False,
              help='保存结果到数据库')
def scan(target: str, modules: tuple, output: str, report_format: str, 
         config_file: Optional[str], timeout: int, concurrency: int,
         proxy: str, save_db: bool):
    """
    执行完整扫描
    
    TARGET: 扫描目标 (域名、IP或URL)
    """
    scanner = create_scanner(config_file)
    
    if timeout:
        scanner.config.scan.timeout = timeout
    if concurrency:
        scanner.config.scan.concurrency = concurrency
    if proxy:
        scanner.config.scan.proxy = proxy
    
    module_list = list(modules) if modules else None
    
    async def run():
        report = await scanner.scan(target, module_list)
        scanner.save_results(report, output, report_format)
        
        if save_db:
            scan_id = db.create_scan(target, module_list or [])
            for result in report.results:
                db.add_finding(scan_id, result.to_dict())
            db.update_scan(scan_id, status="completed", 
                          total_findings=len(report.results))
            logger.success(f"结果已保存到数据库，扫描ID: {scan_id}")
        
        return report
    
    asyncio.run(run())


@cli.command()
@click.argument('target_file', type=click.Path(exists=True))
@click.option('--modules', '-m', multiple=True, help='指定模块')
@click.option('--concurrency', '-c', default=3, help='并发扫描数')
@click.option('--output-dir', '-o', default='outputs/batch', help='输出目录')
@click.option('--save-db', is_flag=True, default=True, help='保存到数据库')
def batch(target_file: str, modules: tuple, concurrency: int, 
          output_dir: str, save_db: bool):
    """
    批量扫描
    
    TARGET_FILE: 目标文件路径，每行一个目标
    """
    from modules.recon.batch_scanner import BatchScanner
    
    async def run():
        scanner = BatchScanner()
        results = await scanner.scan_from_file(
            target_file, 
            list(modules) if modules else None,
            concurrency,
            save_db
        )
        
        if results:
            scanner.save_results(output_dir)
            scanner.export_summary(f"{output_dir}/summary.csv")
        
        return results
    
    asyncio.run(run())


@cli.command()
@click.argument('target')
@click.option('--ports', '-p', default='common',
              help='端口范围 (common, top100, top1000, 或 1-1000)')
@click.option('--service-detection', is_flag=True, default=True,
              help='启用服务识别')
@click.option('--os-detection', is_flag=True, default=False,
              help='启用操作系统识别')
@click.option('--output', '-o', default=None,
              help='结果输出文件')
def portscan(target: str, ports: str, service_detection: bool, 
             os_detection: bool, output: Optional[str]):
    """
    端口扫描
    
    TARGET: 目标主机名或IP地址
    """
    from modules.recon.advanced_port_scanner import AdvancedPortScanner
    
    async def run():
        scanner = AdvancedPortScanner()
        scanner.timeout = 3.0
        scanner.service_detection = service_detection
        
        results = await scanner.scan(target)
        
        if output:
            import json
            with open(output, 'w') as f:
                json.dump([r.to_dict() for r in results], f, indent=2, ensure_ascii=False)
            logger.success(f"结果已保存到: {output}")
        
        return results
    
    logger.print_banner()
    asyncio.run(run())


@cli.command()
@click.argument('url')
@click.option('--depth', '-d', default=3, help='爬取深度')
@click.option('--max-pages', default=100, help='最大页面数')
@click.option('--output', '-o', default=None, help='结果输出文件')
def crawl(url: str, depth: int, max_pages: int, output: Optional[str]):
    """
    Web爬虫
    
    URL: 目标URL
    """
    from modules.recon.web_crawler import WebCrawler
    
    async def run():
        scanner = WebCrawler()
        scanner.max_depth = depth
        scanner.max_pages = max_pages
        
        results = await scanner.scan(url)
        
        if output:
            import json
            with open(output, 'w') as f:
                json.dump([r.to_dict() for r in results], f, indent=2, ensure_ascii=False)
            logger.success(f"结果已保存到: {output}")
        
        return results
    
    logger.print_banner()
    asyncio.run(run())


@cli.command()
@click.argument('url')
def fingerprint(url: str):
    """
    指纹识别
    
    URL: 目标URL
    """
    from modules.recon.fingerprint import FingerprintScanner
    
    async def run():
        scanner = FingerprintScanner()
        results = await scanner.scan(url)
        return results
    
    logger.print_banner()
    asyncio.run(run())


@cli.command()
@click.argument('url')
@click.option('--output', '-o', default=None, help='结果输出文件')
def poc(url: str, output: Optional[str]):
    """
    POC漏洞验证
    
    URL: 目标URL
    """
    from modules.vulnscan.poc_scanner import POCScanner
    
    async def run():
        scanner = POCScanner()
        results = await scanner.scan(url)
        
        if output:
            import json
            with open(output, 'w') as f:
                json.dump([r.to_dict() for r in results], f, indent=2, ensure_ascii=False)
        
        return results
    
    logger.print_banner()
    asyncio.run(run())


@cli.command()
@click.argument('url')
@click.option('--output', '-o', default=None, help='结果输出文件')
def sqli(url: str, output: Optional[str]):
    """SQL注入扫描"""
    from modules.vulnscan.sql_injection import SQLInjectionScanner
    
    async def run():
        scanner = SQLInjectionScanner()
        results = await scanner.scan(url)
        
        if output:
            import json
            with open(output, 'w') as f:
                json.dump([r.to_dict() for r in results], f, indent=2, ensure_ascii=False)
        
        return results
    
    logger.print_banner()
    asyncio.run(run())


@cli.command()
@click.argument('url')
@click.option('--output', '-o', default=None, help='结果输出文件')
def xss(url: str, output: Optional[str]):
    """XSS漏洞扫描"""
    from modules.vulnscan.xss_scanner import XSSScanner
    
    async def run():
        scanner = XSSScanner()
        results = await scanner.scan(url)
        
        if output:
            import json
            with open(output, 'w') as f:
                json.dump([r.to_dict() for r in results], f, indent=2, ensure_ascii=False)
        
        return results
    
    logger.print_banner()
    asyncio.run(run())


@cli.command()
@click.argument('url')
@click.option('--output', '-o', default=None, help='结果输出文件')
def sensitive(url: str, output: Optional[str]):
    """敏感信息扫描"""
    from modules.vulnscan.sensitive_info import SensitiveInfoScanner
    
    async def run():
        scanner = SensitiveInfoScanner()
        results = await scanner.scan(url)
        
        if output:
            import json
            with open(output, 'w') as f:
                json.dump([r.to_dict() for r in results], f, indent=2, ensure_ascii=False)
        
        return results
    
    logger.print_banner()
    asyncio.run(run())


@cli.command('list-modules')
def list_modules():
    """列出所有可用模块"""
    scanner = create_scanner()
    modules = scanner.get_available_modules()
    
    logger.print_banner()
    logger.info("\n可用模块列表:\n")
    
    for module_name in modules:
        info = scanner.get_module_info(module_name)
        if info:
            # 使用普通字符避免在 Windows GBK 控制台下编码错误
            click.echo(f"  - {module_name}")
            click.echo(f"    名称: {info['name']}")
            click.echo(f"    描述: {info['description']}")
            click.echo(f"    版本: {info['version']}")
            click.echo()


@cli.command()
@click.option('--host', '-h', default='0.0.0.0', help='监听地址')
@click.option('--port', '-p', default=8000, help='监听端口')
def web(host: str, port: int):
    """启动Web界面"""
    from web.app import run_server
    run_server(host=host, port=port)


@cli.command()
def init():
    """初始化项目配置"""
    config = Config()
    config.save_config('config.yaml')
    logger.success("配置文件已创建: config.yaml")
    
    Path('logs').mkdir(exist_ok=True)
    Path('outputs').mkdir(exist_ok=True)
    Path('data/wordlists').mkdir(parents=True, exist_ok=True)
    Path('data/payloads').mkdir(parents=True, exist_ok=True)
    
    logger.success("项目目录结构已创建")


@cli.command()
def stats():
    """查看扫描统计"""
    stats = db.get_stats()
    
    logger.print_banner()
    logger.info("\n扫描统计:\n")
    click.echo(f"  总扫描数: {stats['total_scans']}")
    click.echo(f"  总发现数: {stats['total_findings']}")
    click.echo(f"  近7天扫描: {stats['recent_scans_7d']}")
    click.echo("\n  严重程度分布:")
    for sev, count in stats['severity_distribution'].items():
        click.echo(f"    {sev}: {count}")


@cli.command()
@click.option('--limit', '-l', default=20, help='显示数量')
def history(limit: int):
    """查看扫描历史"""
    scans = db.get_scans(limit=limit)
    
    logger.print_banner()
    logger.info("\n扫描历史:\n")
    
    for s in scans:
        click.echo(f"  [{s.id}] {s.target}")
        click.echo(f"      状态: {s.status} | 发现: {s.total_findings} | 时间: {s.start_time}")
        click.echo()


@cli.command()
@click.argument('query')
@click.option('--severity', '-s', default=None, help='按严重程度过滤')
def search(query: str, severity: Optional[str]):
    """搜索扫描结果"""
    findings = db.search_findings(query, severity)
    
    logger.print_banner()
    logger.info(f"\n搜索结果 ({len(findings)} 条):\n")
    
    for f in findings:
        click.echo(f"  [{f.severity.upper()}] {f.title}")
        click.echo(f"      目标: {f.target}")
        click.echo()


if __name__ == '__main__':
    cli()
