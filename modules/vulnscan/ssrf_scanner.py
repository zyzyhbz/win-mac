"""
SSRF（服务端请求伪造）检测模块
检测应用是否存在SSRF漏洞
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, urlencode

from core.base import BaseModule, ScanResult, Severity, ResultType
from core.logger import Logger


@dataclass
class SSRFPoint:
    """SSRF注入点"""
    parameter: str
    injection_type: str
    payload: str
    evidence: str


# SSRF测试Payload
SSRF_PAYLOADS = [
    # 内网IP
    ("http://127.0.0.1", "internal_ip"),
    ("http://localhost", "internal_ip"),
    ("http://[::1]", "internal_ip"),
    ("http://0.0.0.0", "internal_ip"),
    
    # 内网IP段
    ("http://192.168.1.1", "internal_ip"),
    ("http://10.0.0.1", "internal_ip"),
    ("http://172.16.0.1", "internal_ip"),
    
    # DNS重绑定
    ("http://spoofed.burpcollaborator.net", "dns_rebinding"),
    
    # 协议利用
    ("file:///etc/passwd", "file_protocol"),
    ("file:///c:/windows/win.ini", "file_protocol"),
    ("gopher://127.0.0.1:70", "gopher_protocol"),
    ("dict://127.0.0.1:6379/info", "dict_protocol"),
    
    # 绕过技巧
    ("http://127.0.0.1@example.com", "bypass"),
    ("http://example.com@127.0.0.1", "bypass"),
    ("http://127.0.0.1#.example.com", "bypass"),
    ("http://127.1", "bypass"),
    ("http://2130706433", "bypass"),  # 127.0.0.1的十进制
    ("http://0x7f000001", "bypass"),  # 127.0.0.1的十六进制
    ("http://127.0.0.1.nip.io", "bypass"),
]

# SSRF响应特征
SSRF_INDICATORS = [
    r"root:x:0:0",  # /etc/passwd
    r"\[fonts\]",   # win.ini
    r"redis_version",
    r"SSH-",
    r"MySQL",
    r"connection refused",
    r"connection timed out",
    r"network is unreachable",
]


class SSRFScanner(BaseModule):
    """
    SSRF漏洞扫描器
    检测服务端请求伪造漏洞
    """
    
    name = "ssrf_scanner"
    description = "SSRF服务端请求伪造漏洞检测器"
    author = "PySecScanner"
    version = "1.0.0"
    
    def __init__(self, config=None, logger=None):
        super().__init__(config, logger)
        self.timeout = 15
        self.concurrency = 5
        self.payloads = SSRF_PAYLOADS
        self.ssrF_points: List[SSRFPoint] = []
        self.base_url = ""
    
    async def scan(self, target: str) -> List[ScanResult]:
        """
        执行SSRF扫描
        
        Args:
            target: 目标URL
        """
        self.base_url = self._normalize_url(target)
        if not self.base_url:
            self.logger.error(f"无效的URL: {target}")
            return []
        
        self.logger.info(f"目标URL: {self.base_url}")
        
        # 解析参数
        params = self._extract_parameters(self.base_url)
        if not params:
            self.logger.warning("未发现可测试的参数")
            return []
        
        self.logger.info(f"发现参数: {', '.join(params.keys())}")
        
        # 执行SSRF测试
        self.ssrf_points = await self._test_ssrf(params)
        
        # 生成结果
        results = []
        for ssrf in self.ssrf_points:
            result = ScanResult(
                result_type=ResultType.VULNERABILITY,
                title=f"SSRF漏洞: {ssrf.parameter}",
                description=f"参数 '{ssrf.parameter}' 存在SSRF漏洞，类型: {ssrf.injection_type}",
                severity=Severity.HIGH,
                target=self.base_url,
                evidence=f"参数: {ssrf.parameter}\nPayload: {ssrf.payload}\n证据: {ssrf.evidence}",
                raw_data=ssrf.__dict__
            )
            results.append(result)
            self.add_result(result)
        
        if self.ssrf_points:
            self.logger.print_result(
                "发现的SSRF漏洞",
                [f"{s.parameter} ({s.injection_type})" for s in self.ssrf_points]
            )
        else:
            self.logger.info("未发现SSRF漏洞")
        
        return results
    
    def _normalize_url(self, url: str) -> str:
        """规范化URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url
    
    def _extract_parameters(self, url: str) -> Dict[str, str]:
        """提取URL参数"""
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = {}
        
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for key, values in query_params.items():
                params[key] = values[0] if values else ""
        
        return params
    
    async def _test_ssrf(self, params: Dict[str, str]) -> List[SSRFPoint]:
        """测试SSRF漏洞"""
        semaphore = asyncio.Semaphore(self.concurrency)
        ssrf_points: List[SSRFPoint] = []
        tested = set()
        
        connector = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async def test_param(param_name: str, original_value: str) -> Optional[SSRFPoint]:
            async with semaphore:
                for payload, inj_type in self.payloads:
                    test_key = f"{param_name}:{payload[:30]}"
                    if test_key in tested:
                        continue
                    tested.add(test_key)
                    
                    # 构造测试URL
                    test_params = params.copy()
                    test_params[param_name] = payload
                    test_url = self._build_url(test_params)
                    
                    try:
                        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                            async with session.get(test_url) as response:
                                content = await response.text()
                                
                                # 检查SSRF特征
                                for pattern in SSRF_INDICATORS:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        return SSRFPoint(
                                            parameter=param_name,
                                            injection_type=inj_type,
                                            payload=payload,
                                            evidence=f"匹配模式: {pattern}"
                                        )
                                
                                # 检查响应差异
                                # 如果响应与正常请求差异很大，可能存在SSRF
                                
                    except asyncio.TimeoutError:
                        # 超时可能表示请求被发送到内网
                        if "127.0.0.1" in payload or "localhost" in payload:
                            pass  # 可能存在SSRF但内网不可达
                    except Exception:
                        pass
                
                return None
        
        tasks = [test_param(name, value) for name, value in params.items()]
        
        completed = 0
        total = len(tasks)
        
        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed += 1
            self.logger.print_progress(completed, total, "SSRF测试中")
            
            if result:
                ssrf_points.append(result)
        
        print()
        
        return ssrf_points
    
    def _build_url(self, params: Dict[str, str]) -> str:
        """构建测试URL"""
        from urllib.parse import urlencode, urlparse, urlunparse
        parsed = urlparse(self.base_url)
        query = urlencode(params)
        
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            query,
            parsed.fragment
        ))
