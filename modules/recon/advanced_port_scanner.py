"""
增强版端口扫描模块
支持TCP连接扫描、服务版本探测、操作系统识别
"""

import asyncio
import socket
import re
import os
from typing import List, Optional, Dict
from dataclasses import dataclass, field

from core.base import BaseModule, ScanResult, Severity, ResultType
from core.logger import logger as global_logger


@dataclass
class ServiceInfo:
    """服务信息"""
    name: str
    version: str = ""
    product: str = ""


@dataclass
class PortInfo:
    """端口信息"""
    port: int
    status: str
    protocol: str = "tcp"
    service: ServiceInfo = None
    banner: str = ""


@dataclass
class HostInfo:
    """主机信息"""
    ip: str
    hostname: str = ""
    os_match: str = ""
    os_accuracy: int = 0


# 服务探测探针
SERVICE_PROBES = {
    "http": [b"GET / HTTP/1.0\r\n\r\n"],
    "ssh": [b"SSH-2.0-PySecScanner\r\n"],
    "ftp": [b"USER anonymous\r\n"],
    "smtp": [b"EHLO localhost\r\n"],
    "mysql": [b"\x00\x00\x00\x00\x00\x00\x00\x00\x00"],
    "redis": [b"INFO\r\n"],
}

# 常见端口服务映射
PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    9200: "elasticsearch", 27017: "mongodb",
}

# 服务识别正则
SERVICE_PATTERNS = {
    "ssh": [(r"SSH-([\d.]+)-(.+)", lambda m: ServiceInfo("ssh", m.group(2), version=m.group(1)))],
    "http": [(r"Server:\s*(.+)", lambda m: ServiceInfo("http", product=m.group(1).strip()))],
    "mysql": [(r"(\d+\.\d+\.\d+)", lambda m: ServiceInfo("mysql", version=m.group(1)))],
    "redis": [(r"redis_version:(\d+\.\d+)", lambda m: ServiceInfo("redis", version=m.group(1)))],
    "ftp": [(r"(\d+)\s+(.+)?FTP", lambda m: ServiceInfo("ftp", product=m.group(2) or "FTP"))],
}


class AdvancedPortScanner(BaseModule):
    """
    增强版端口扫描器
    支持多种扫描方式和服务识别
    """
    
    name = "advanced_port_scanner"
    description = "增强版端口扫描器，支持服务版本探测"
    author = "PySecScanner"
    version = "2.0.0"
    
    def __init__(self, config=None, logger=None):
        super().__init__(config, logger)
        # 确保logger不为None
        if self.logger is None:
            self.logger = global_logger
        
        self.timeout = 2.0
        self.concurrency = 100
        self.service_detection = True
        self.open_ports: List[PortInfo] = []
        self.host_info: Optional[HostInfo] = None
    
    async def scan(self, target: str) -> List[ScanResult]:
        """执行端口扫描"""
        # 解析目标
        ip = await self._resolve_target(target)
        if not ip:
            self.logger.error(f"无法解析目标: {target}")
            return []
        
        # 初始化主机信息
        self.host_info = HostInfo(ip=ip, hostname=target if target != ip else "")
        
        self.logger.info(f"目标IP: {ip}")
        
        # 解析端口范围
        ports = self._parse_ports("common")
        self.logger.info(f"扫描端口: {len(ports)} 个")
        
        # 执行扫描
        self.open_ports = await self._tcp_connect_scan(ip, ports)
        
        # 服务识别
        if self.open_ports and self.service_detection:
            self.logger.info("正在进行服务识别...")
            await self._detect_services(ip, self.open_ports)
        
        # 操作系统识别
        if self.open_ports:
            self._os_detection()
        
        # 生成结果
        results = []
        
        # 主机信息结果
        if self.host_info.os_match:
            results.append(ScanResult(
                result_type=ResultType.INFO,
                title=f"操作系统识别: {self.host_info.os_match}",
                description=f"目标系统可能是 {self.host_info.os_match} (置信度: {self.host_info.os_accuracy}%)",
                severity=Severity.INFO,
                target=ip,
                evidence=f"OS: {self.host_info.os_match}\nAccuracy: {self.host_info.os_accuracy}%",
                raw_data={'os': self.host_info.os_match, 'accuracy': self.host_info.os_accuracy}
            ))
        
        # 端口结果
        for port_info in self.open_ports:
            service_str = ""
            if port_info.service:
                service_str = f"{port_info.service.name}"
                if port_info.service.version:
                    service_str += f" {port_info.service.version}"
                if port_info.service.product:
                    service_str += f" ({port_info.service.product})"
            
            result = ScanResult(
                result_type=ResultType.PORT,
                title=f"开放端口: {port_info.port}/{port_info.protocol}",
                description=f"端口 {port_info.port} 处于 {port_info.status} 状态",
                severity=Severity.INFO,
                target=f"{ip}:{port_info.port}",
                evidence=f"服务: {service_str or 'unknown'}\nBanner: {port_info.banner[:200] if port_info.banner else 'N/A'}",
                raw_data={
                    'port': port_info.port,
                    'status': port_info.status,
                    'protocol': port_info.protocol,
                    'banner': port_info.banner
                }
            )
            results.append(result)
            self.add_result(result)
        
        # 打印结果
        if self.open_ports:
            self.logger.print_result(
                "开放端口",
                [f"{p.port}/{p.protocol} - {p.service.name if p.service else 'unknown'}" 
                 for p in self.open_ports[:20]]
            )
            if len(self.open_ports) > 20:
                self.logger.info(f"    ... 还有 {len(self.open_ports) - 20} 个端口")
        else:
            self.logger.info("未发现开放端口")
        
        return results
    
    async def _resolve_target(self, target: str) -> Optional[str]:
        """解析目标为IP地址"""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.getaddrinfo(target, None)
            if result:
                return result[0][4][0]
        except socket.gaierror:
            pass
        return None
    
    def _parse_ports(self, port_spec: str) -> List[int]:
        """解析端口规格"""
        presets = {
            "common": [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 
                      1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017],
            "top100": list(range(1, 101)),
            "top1000": list(range(1, 1001)),
        }
        
        if port_spec.lower() in presets:
            return presets[port_spec.lower()]
        
        ports = set()
        for part in port_spec.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.update(range(int(start), int(end) + 1))
            else:
                ports.add(int(part))
        
        return sorted(ports)
    
    async def _tcp_connect_scan(self, ip: str, ports: List[int]) -> List[PortInfo]:
        """TCP连接扫描"""
        semaphore = asyncio.Semaphore(self.concurrency)
        open_ports = []
        
        async def scan_port(port: int) -> Optional[PortInfo]:
            async with semaphore:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=self.timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    
                    service_name = PORT_SERVICES.get(port, "unknown")
                    return PortInfo(
                        port=port, 
                        status="open", 
                        protocol="tcp",
                        service=ServiceInfo(name=service_name)
                    )
                except:
                    return None
        
        tasks = [scan_port(port) for port in ports]
        completed = 0
        total = len(tasks)
        
        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed += 1
            
            if completed % 10 == 0 or completed == total:
                self.logger.print_progress(completed, total, "TCP扫描中")
            
            if result:
                open_ports.append(result)
        
        print()
        return sorted(open_ports, key=lambda x: x.port)
    
    async def _detect_services(self, ip: str, ports: List[PortInfo]) -> None:
        """服务版本探测"""
        for port_info in ports:
            try:
                banner = await self._grab_banner(ip, port_info.port)
                if banner:
                    port_info.banner = banner
                    service = self._parse_service_banner(banner, port_info.port)
                    if service:
                        port_info.service = service
            except:
                pass
    
    async def _grab_banner(self, ip: str, port: int) -> str:
        """获取服务Banner"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            
            service = PORT_SERVICES.get(port, "unknown")
            probes = SERVICE_PROBES.get(service, [b""])
            
            for probe in probes:
                try:
                    writer.write(probe)
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
                    if data:
                        writer.close()
                        await writer.wait_closed()
                        return data.decode('utf-8', errors='ignore')
                except:
                    continue
            
            writer.close()
            await writer.wait_closed()
        except:
            pass
        
        return ""
    
    def _parse_service_banner(self, banner: str, port: int) -> Optional[ServiceInfo]:
        """解析Banner获取服务信息"""
        service_name = PORT_SERVICES.get(port, "unknown")
        
        for svc_name, patterns in SERVICE_PATTERNS.items():
            for pattern, extractor in patterns:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    try:
                        return extractor(match)
                    except:
                        pass
        
        return ServiceInfo(name=service_name)
    
    def _os_detection(self) -> None:
        """操作系统识别"""
        if not self.open_ports:
            return
        
        port_set = {p.port for p in self.open_ports}
        
        windows_ports = {135, 139, 445, 3389}
        linux_ports = {22, 111}
        
        windows_score = len(port_set & windows_ports)
        linux_score = len(port_set & linux_ports)
        
        if windows_score > linux_score:
            self.host_info.os_match = "Windows"
            self.host_info.os_accuracy = min(80, 50 + windows_score * 10)
        elif linux_score > 0:
            self.host_info.os_match = "Linux"
            self.host_info.os_accuracy = min(80, 50 + linux_score * 10)
        else:
            self.host_info.os_match = "Unknown"
            self.host_info.os_accuracy = 0
