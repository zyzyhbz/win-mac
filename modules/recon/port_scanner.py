"""
端口扫描模块
支持TCP连接扫描、服务识别
"""

import asyncio
import socket
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

from core.base import BaseModule, ScanResult, Severity, ResultType
from core.logger import Logger


@dataclass
class PortInfo:
    """端口信息"""
    port: int
    status: str  # open, closed, filtered
    service: str = ""
    version: str = ""
    banner: str = ""


# 常见端口服务映射
COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "rpc",
    139: "netbios",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    9000: "php-fpm",
    9200: "elasticsearch",
    27017: "mongodb",
}


class PortScanner(BaseModule):
    """
    端口扫描器
    使用异步TCP连接扫描检测开放端口
    """
    
    name = "port_scanner"
    description = "TCP端口扫描器，支持服务识别"
    author = "PySecScanner"
    version = "1.0.0"
    
    def __init__(self, config=None, logger=None):
        super().__init__(config, logger)
        self.timeout = 2.0
        self.concurrency = 100
        self.open_ports: List[PortInfo] = []
    
    async def scan(self, target: str) -> List[ScanResult]:
        """
        执行端口扫描
        
        Args:
            target: 目标主机名或IP地址
            
        Returns:
            扫描结果列表
        """
        # 解析目标
        ip = await self._resolve_target(target)
        if not ip:
            self.logger.error(f"无法解析目标: {target}")
            return []
        
        self.logger.info(f"目标IP: {ip}")
        
        # 解析端口范围
        ports = self._parse_ports(self.config.port_scan.ports if self.config else "1-1000")
        self.logger.info(f"扫描端口: {len(ports)} 个")
        
        # 执行扫描
        self.open_ports = await self._scan_ports(ip, ports)
        
        # 服务识别
        if self.open_ports:
            self.logger.info("正在进行服务识别...")
            await self._detect_services(ip, self.open_ports)
        
        # 生成结果
        results = []
        for port_info in self.open_ports:
            result = ScanResult(
                result_type=ResultType.PORT,
                title=f"开放端口: {port_info.port}",
                description=f"端口 {port_info.port} 处于开放状态",
                severity=Severity.INFO,
                target=f"{ip}:{port_info.port}",
                evidence=f"服务: {port_info.service}\n版本: {port_info.version}\nBanner: {port_info.banner[:100] if port_info.banner else 'N/A'}",
                raw_data=port_info.__dict__
            )
            results.append(result)
            self.add_result(result)
        
        # 打印结果
        if self.open_ports:
            self.logger.print_result(
                "开放端口",
                [f"{p.port}/{p.service or 'unknown'} - {p.version or 'version unknown'}" 
                 for p in self.open_ports]
            )
        
        return results
    
    async def _resolve_target(self, target: str) -> Optional[str]:
        """解析目标为IP地址"""
        try:
            # 尝试直接解析
            loop = asyncio.get_event_loop()
            result = await loop.getaddrinfo(target, None)
            if result:
                return result[0][4][0]
        except socket.gaierror:
            pass
        return None
    
    def _parse_ports(self, port_spec: str) -> List[int]:
        """
        解析端口规格
        
        支持格式:
        - "80" - 单个端口
        - "80,443,8080" - 多个端口
        - "1-1000" - 端口范围
        - "1-100,443,8080-8090" - 混合格式
        """
        ports = set()
        
        for part in port_spec.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.update(range(int(start), int(end) + 1))
            else:
                ports.add(int(part))
        
        return sorted(ports)
    
    async def _scan_ports(self, ip: str, ports: List[int]) -> List[PortInfo]:
        """异步扫描端口"""
        semaphore = asyncio.Semaphore(self.concurrency)
        open_ports = []
        
        async def scan_single_port(port: int) -> Optional[PortInfo]:
            async with semaphore:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=self.timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    
                    service = COMMON_SERVICES.get(port, "unknown")
                    return PortInfo(port=port, status="open", service=service)
                    
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return None
            
        # 创建扫描任务
        tasks = [scan_single_port(port) for port in ports]
        
        # 使用进度显示
        completed = 0
        total = len(tasks)
        
        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed += 1
            
            if completed % 100 == 0 or completed == total:
                self.logger.print_progress(completed, total, f"端口扫描中")
            
            if result:
                open_ports.append(result)
        
        print()  # 换行
        
        return sorted(open_ports, key=lambda x: x.port)
    
    async def _detect_services(self, ip: str, ports: List[PortInfo]) -> None:
        """服务识别"""
        for port_info in ports:
            try:
                banner = await self._grab_banner(ip, port_info.port)
                if banner:
                    port_info.banner = banner
                    service, version = self._parse_banner(banner)
                    if service:
                        port_info.service = service
                    if version:
                        port_info.version = version
            except Exception:
                pass
    
    async def _grab_banner(self, ip: str, port: int) -> str:
        """获取服务Banner"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            
            # 发送探测请求
            probe = b"HEAD / HTTP/1.0\r\n\r\n"
            writer.write(probe)
            await writer.drain()
            
            # 读取响应
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                writer.close()
                await writer.wait_closed()
                return data.decode('utf-8', errors='ignore')
            except asyncio.TimeoutError:
                writer.close()
                await writer.wait_closed()
                return ""
                
        except Exception:
            return ""
    
    def _parse_banner(self, banner: str) -> Tuple[str, str]:
        """解析Banner获取服务信息"""
        service = ""
        version = ""
        
        # HTTP Server头
        match = re.search(r'Server:\s*([^\r\n]+)', banner, re.IGNORECASE)
        if match:
            server = match.group(1)
            service = server.split('/')[0].lower()
            version_match = re.search(r'/([\d.]+)', server)
            if version_match:
                version = version_match.group(1)
        
        # SSH
        if 'SSH' in banner:
            service = 'ssh'
            match = re.search(r'SSH-[\d.]+-([^\r\n]+)', banner)
            if match:
                version = match.group(1)
        
        # FTP
        if banner.startswith('220') and 'FTP' in banner:
            service = 'ftp'
            match = re.search(r'220.*?([^\s]+)\s+FTP', banner, re.IGNORECASE)
            if match:
                version = match.group(1)
        
        # MySQL
        if 'mysql' in banner.lower():
            service = 'mysql'
            match = re.search(r'(\d+\.[\d.]+)', banner)
            if match:
                version = match.group(1)
        
        return service, version
