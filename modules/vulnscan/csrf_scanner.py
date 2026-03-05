"""
CSRF（跨站请求伪造）检测模块
检测表单是否存在CSRF保护
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional
from dataclasses import dataclass
from urllib.parse import urlparse

from core.base import BaseModule, ScanResult, Severity, ResultType
from core.logger import Logger


@dataclass
class CSRFVulnerability:
    """CSRF漏洞信息"""
    form_url: str
    form_action: str
    method: str
    missing_token: bool
    missing_referer_check: bool
    description: str


class CSRFScanner(BaseModule):
    """
    CSRF漏洞扫描器
    检测表单是否缺少CSRF保护
    """
    
    name = "csrf_scanner"
    description = "CSRF跨站请求伪造漏洞检测器"
    author = "PySecScanner"
    version = "1.0.0"
    
    def __init__(self, config=None, logger=None):
        super().__init__(config, logger)
        self.timeout = 10
        self.vulnerabilities: List[CSRFVulnerability] = []
        self.base_url = ""
        
        # CSRF Token常见名称
        self.token_names = [
            'csrf_token', 'csrftoken', 'csrf', '_token', 'token',
            'authenticity_token', '_csrf', 'csrfmiddlewaretoken',
            '__RequestVerificationToken', 'antiForgeryToken',
            'nonce', 'token_', 'form_token', 'security_token'
        ]
    
    async def scan(self, target: str) -> List[ScanResult]:
        """
        执行CSRF扫描
        
        Args:
            target: 目标URL
        """
        self.base_url = self._normalize_url(target)
        if not self.base_url:
            self.logger.error(f"无效的URL: {target}")
            return []
        
        self.logger.info(f"目标URL: {self.base_url}")
        
        # 获取页面内容
        forms = await self._extract_forms(self.base_url)
        
        if not forms:
            self.logger.warning("未发现表单")
            return []
        
        self.logger.info(f"发现 {len(forms)} 个表单")
        
        # 分析每个表单
        for form in forms:
            vuln = self._analyze_form(form)
            if vuln:
                self.vulnerabilities.append(vuln)
        
        # 生成结果
        results = []
        for vuln in self.vulnerabilities:
            result = ScanResult(
                result_type=ResultType.VULNERABILITY,
                title=f"CSRF漏洞: {vuln.form_action}",
                description=vuln.description,
                severity=Severity.MEDIUM,
                target=vuln.form_url,
                evidence=f"表单URL: {vuln.form_url}\n"
                        f"Action: {vuln.form_action}\n"
                        f"方法: {vuln.method}\n"
                        f"缺少Token: {vuln.missing_token}\n"
                        f"缺少Referer检查: {vuln.missing_referer_check}",
                raw_data=vuln.__dict__
            )
            results.append(result)
            self.add_result(result)
        
        if self.vulnerabilities:
            self.logger.print_result(
                "发现的CSRF漏洞",
                [f"{v.form_action} ({v.method})" for v in self.vulnerabilities]
            )
        else:
            self.logger.info("未发现CSRF漏洞")
        
        return results
    
    def _normalize_url(self, url: str) -> str:
        """规范化URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url
    
    async def _extract_forms(self, url: str) -> List[Dict]:
        """提取页面中的表单"""
        forms = []
        
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get(url) as response:
                    html = await response.text()
                    
                    # 提取表单
                    form_pattern = re.compile(
                        r'<form[^>]*action=["\']?([^"\'>\s]*)["\']?[^>]*method=["\']?([^"\'>\s]*)["\']?[^>]*>(.*?)</form>',
                        re.IGNORECASE | re.DOTALL
                    )
                    
                    for match in form_pattern.finditer(html):
                        action = match.group(1) or url
                        method = match.group(2).upper() or 'GET'
                        form_html = match.group(3)
                        
                        # 提取输入字段
                        inputs = re.findall(
                            r'<input[^>]*name=["\']?([^"\'>\s]+)["\']?[^>]*>',
                            form_html,
                            re.IGNORECASE
                        )
                        
                        forms.append({
                            'url': url,
                            'action': action,
                            'method': method,
                            'inputs': inputs,
                            'html': form_html
                        })
                        
        except Exception as e:
            self.logger.warning(f"获取页面失败: {e}")
        
        return forms
    
    def _analyze_form(self, form: Dict) -> Optional[CSRFVulnerability]:
        """分析表单是否存在CSRF漏洞"""
        # 只检查POST/PUT/DELETE表单
        if form['method'] not in ['POST', 'PUT', 'DELETE']:
            return None
        
        # 检查是否存在CSRF Token
        has_token = False
        form_html_lower = form['html'].lower()
        
        for token_name in self.token_names:
            if token_name.lower() in form_html_lower:
                has_token = True
                break
        
        # 检查是否有隐藏字段
        has_hidden = bool(re.search(r'type=["\']?hidden["\']?', form['html'], re.IGNORECASE))
        
        # 如果没有Token，可能存在CSRF漏洞
        if not has_token:
            return CSRFVulnerability(
                form_url=form['url'],
                form_action=form['action'],
                method=form['method'],
                missing_token=True,
                missing_referer_check=True,  # 假设没有Referer检查
                description=f"表单 {form['action']} 缺少CSRF Token保护，攻击者可以伪造用户请求"
            )
        
        return None
    
    async def _test_referer_check(self, form: Dict) -> bool:
        """测试是否存在Referer检查"""
        # 发送不带Referer的请求
        # 发送带外部Referer的请求
        # 比较响应
        # 这里简化处理
        return False
