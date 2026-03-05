"""
SQL注入检测模块
支持多种注入类型检测
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.base import BaseModule, ScanResult, Severity, ResultType
from core.logger import Logger


@dataclass
class InjectionPoint:
    """注入点信息"""
    parameter: str
    injection_type: str  # GET, POST, Header, Cookie
    payload: str
    evidence: str


# SQL注入测试Payload
SQL_PAYLOADS = [
    # 基于错误的注入
    ("'", "error", r"(sql|mysql|sqlite|postgresql|oracle|syntax|query|unexpected)"),
    ("\"", "error", r"(sql|mysql|sqlite|postgresql|oracle|syntax|query|unexpected)"),
    ("'", "error", r"('|\")?[^'\"]*(SQL|syntax|mysql|oracle|postgres|sqlite)[^'\"]*"),
    
    # 布尔盲注
    ("' AND 1=1--", "boolean", None),
    ("' AND 1=2--", "boolean", None),
    ("' OR '1'='1", "boolean", None),
    ("1' AND '1'='1", "boolean", None),
    ("1' AND '1'='2", "boolean", None),
    
    # 时间盲注
    ("' AND SLEEP(3)--", "time", None),
    ("' AND BENCHMARK(5000000,SHA1('test'))--", "time", None),
    ("'; WAITFOR DELAY '0:0:3'--", "time", None),
    
    # UNION注入
    ("' UNION SELECT NULL--", "union", None),
    ("' UNION SELECT NULL,NULL--", "union", None),
    ("' UNION SELECT NULL,NULL,NULL--", "union", None),
    
    # 数字型注入
    ("1 OR 1=1", "numeric", None),
    ("1 AND 1=1", "numeric", None),
    ("1 AND 1=2", "numeric", None),
]

# SQL错误特征
SQL_ERROR_PATTERNS = [
    r"SQL syntax.*?MySQL",
    r"Warning.*?mysql_",
    r"MySqlException",
    r"PostgreSQL.*?ERROR",
    r"Warning.*?pg_",
    r"Invalid query",
    r"SQLite/JDBCDriver",
    r"SQLite.Exception",
    r"System.Data.SQLite.SQLiteException",
    r"Warning.*?sqlite_",
    r"\[SQL Server\]",
    r"ODBC SQL Server Driver",
    r"SQLServer JDBC Driver",
    r"Oracle error",
    r"Oracle.*?Driver",
    r"Warning.*?oci_",
    r"PLS-\d+:",
    r"ORA-\d+:",
    r"Microsoft SQL Server",
    r"Syntax error.*?query expression",
    r"unterminated quoted string",
    r"quoted string not properly terminated",
]


class SQLInjectionScanner(BaseModule):
    """
    SQL注入扫描器
    检测Web应用中的SQL注入漏洞
    """
    
    name = "sql_injection_scanner"
    description = "SQL注入漏洞检测器"
    author = "PySecScanner"
    version = "1.0.0"
    
    def __init__(self, config=None, logger=None):
        super().__init__(config, logger)
        self.timeout = 15
        self.concurrency = 5
        self.payloads = SQL_PAYLOADS
        self.injection_points: List[InjectionPoint] = []
        self.base_url = ""
    
    async def scan(self, target: str) -> List[ScanResult]:
        """
        执行SQL注入扫描
        
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
        
        # 执行注入测试
        self.injection_points = await self._test_injections(params)
        
        # 生成结果
        results = []
        for injection in self.injection_points:
            result = ScanResult(
                result_type=ResultType.VULNERABILITY,
                title=f"SQL注入漏洞: {injection.parameter}",
                description=f"参数 '{injection.parameter}' 存在SQL注入漏洞，类型: {injection.injection_type}",
                severity=Severity.HIGH,
                target=self.base_url,
                evidence=f"参数: {injection.parameter}\nPayload: {injection.payload}\n证据: {injection.evidence}",
                raw_data=injection.__dict__
            )
            results.append(result)
            self.add_result(result)
        
        # 打印结果
        if self.injection_points:
            self.logger.print_result(
                "发现的SQL注入漏洞",
                [f"{i.parameter} ({i.injection_type})" for i in self.injection_points]
            )
        else:
            self.logger.info("未发现SQL注入漏洞")
        
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
    
    async def _test_injections(self, params: Dict[str, str]) -> List[InjectionPoint]:
        """测试注入点"""
        semaphore = asyncio.Semaphore(self.concurrency)
        injections: List[InjectionPoint] = []
        tested = set()
        
        connector = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async def test_param(param_name: str, original_value: str) -> Optional[InjectionPoint]:
            async with semaphore:
                for payload, inj_type, pattern in self.payloads:
                    test_key = f"{param_name}:{payload}"
                    if test_key in tested:
                        continue
                    tested.add(test_key)
                    
                    # 构造测试URL
                    test_params = params.copy()
                    test_params[param_name] = original_value + payload
                    test_url = self._build_url(test_params)
                    
                    try:
                        start_time = asyncio.get_event_loop().time()
                        
                        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                            async with session.get(test_url) as response:
                                content = await response.text()
                                elapsed = asyncio.get_event_loop().time() - start_time
                                
                                # 时间盲注检测
                                if inj_type == "time" and elapsed >= 2.5:
                                    self.logger.highlight(f"时间盲注: {param_name}")
                                    return InjectionPoint(
                                        parameter=param_name,
                                        injection_type="time-based blind",
                                        payload=payload,
                                        evidence=f"响应时间: {elapsed:.2f}秒"
                                    )
                                
                                # 错误注入检测
                                if inj_type == "error" and pattern:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        self.logger.highlight(f"错误注入: {param_name}")
                                        return InjectionPoint(
                                            parameter=param_name,
                                            injection_type="error-based",
                                            payload=payload,
                                            evidence=f"检测到SQL错误信息"
                                        )
                                
                                # 检查SQL错误模式
                                for error_pattern in SQL_ERROR_PATTERNS:
                                    if re.search(error_pattern, content, re.IGNORECASE):
                                        self.logger.highlight(f"SQL错误: {param_name}")
                                        return InjectionPoint(
                                            parameter=param_name,
                                            injection_type="error-based",
                                            payload=payload,
                                            evidence=f"匹配模式: {error_pattern}"
                                        )
                                        
                    except asyncio.TimeoutError:
                        # 超时可能是时间盲注
                        if inj_type == "time":
                            return InjectionPoint(
                                parameter=param_name,
                                injection_type="time-based blind",
                                payload=payload,
                                evidence="请求超时，可能存在时间盲注"
                            )
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
            self.logger.print_progress(completed, total, "SQL注入测试中")
            
            if result:
                injections.append(result)
        
        print()
        
        return injections
    
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
