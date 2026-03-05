"""
指纹识别模块
识别Web应用框架、CMS、服务器等技术栈
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field

from core.base import BaseModule, ScanResult, Severity, ResultType
from core.logger import Logger


@dataclass
class Fingerprint:
    """指纹信息"""
    name: str
    category: str  # cms, framework, server, waf, etc.
    version: str = ""
    confidence: int = 0  # 0-100
    evidence: str = ""


# 指纹规则
FINGERPRINT_RULES = [
    # CMS
    {
        "name": "WordPress",
        "category": "cms",
        "patterns": [
            (r'<meta name="generator" content="WordPress', 100),
            (r'/wp-content/', 80),
            (r'/wp-includes/', 80),
            (r'wp-login\.php', 90),
        ],
        "version_pattern": r'WordPress\s*([\d.]+)'
    },
    {
        "name": "Drupal",
        "category": "cms",
        "patterns": [
            (r'<meta name="generator" content="Drupal', 100),
            (r'/sites/default/files/', 90),
            (r'Drupal\.settings', 90),
        ],
        "version_pattern": r'Drupal\s*([\d.]+)'
    },
    {
        "name": "Joomla",
        "category": "cms",
        "patterns": [
            (r'<meta name="generator" content="Joomla', 100),
            (r'/media/jui/', 80),
            (r'/components/com_', 70),
        ],
        "version_pattern": r'Joomla!\s*([\d.]+)'
    },
    
    # 框架
    {
        "name": "Django",
        "category": "framework",
        "patterns": [
            (r'csrfmiddlewaretoken', 90),
            (r'__admin_media_prefix__', 90),
            (r'django', 50),
        ]
    },
    {
        "name": "Flask",
        "category": "framework",
        "patterns": [
            (r'flask', 50),
        ],
        "headers": {"Server": r"Werkzeug"}
    },
    {
        "name": "Laravel",
        "category": "framework",
        "patterns": [
            (r'laravel', 50),
            (r'laravel_session', 90),
            (r'XSRF-TOKEN', 70),
        ]
    },
    {
        "name": "Spring",
        "category": "framework",
        "patterns": [
            (r'Whitelabel Error Page', 90),
            (r'spring', 50),
        ]
    },
    {
        "name": "ASP.NET",
        "category": "framework",
        "patterns": [
            (r'__VIEWSTATE', 90),
            (r'__EVENTVALIDATION', 90),
            (r'\.aspx?', 70),
        ],
        "headers": {"X-AspNet-Version": r"(.+)"}
    },
    {
        "name": "PHP",
        "category": "language",
        "patterns": [
            (r'\.php', 60),
        ],
        "headers": {"X-Powered-By": r"PHP/?([\d.]*)"}
    },
    {
        "name": "Java",
        "category": "language",
        "patterns": [
            (r'\.jsp', 70),
            (r'\.do', 60),
        ],
        "headers": {"Set-Cookie": r"JSESSIONID"}
    },
    
    # 服务器
    {
        "name": "Nginx",
        "category": "server",
        "headers": {"Server": r"nginx/?([\d.]*)"}
    },
    {
        "name": "Apache",
        "category": "server",
        "headers": {"Server": r"Apache/?([\d.]*)"}
    },
    {
        "name": "IIS",
        "category": "server",
        "headers": {"Server": r"Microsoft-IIS/?([\d.]*)"}
    },
    {
        "name": "Tomcat",
        "category": "server",
        "headers": {"Server": r"Apache-Coyote"}
    },
    
    # WAF
    {
        "name": "Cloudflare",
        "category": "waf",
        "headers": {"Server": r"cloudflare", "CF-RAY": r".+"}
    },
    {
        "name": "Akamai",
        "category": "waf",
        "headers": {"X-Akamai-Transformed": r".+"}
    },
    {
        "name": "AWS WAF",
        "category": "waf",
        "headers": {"X-AMZ-CF-ID": r".+"}
    },
    
    # 前端框架
    {
        "name": "React",
        "category": "frontend",
        "patterns": [
            (r'react', 50),
            (r'data-reactroot', 90),
            (r'_reactRootContainer', 90),
        ]
    },
    {
        "name": "Vue.js",
        "category": "frontend",
        "patterns": [
            (r'vue', 50),
            (r'data-v-[a-f0-9]+', 90),
            (r'__vue__', 90),
        ]
    },
    {
        "name": "Angular",
        "category": "frontend",
        "patterns": [
            (r'ng-version', 90),
            (r'ng-app', 80),
            (r'angular', 50),
        ]
    },
    {
        "name": "jQuery",
        "category": "library",
        "patterns": [
            (r'jquery', 50),
            (r'jquery-\d+\.\d+', 90),
        ]
    },
    
    # 数据库
    {
        "name": "MySQL",
        "category": "database",
        "patterns": [
            (r'mysql', 30),
        ]
    },
    {
        "name": "MongoDB",
        "category": "database",
        "patterns": [
            (r'mongodb', 30),
            (r'mongo', 20),
        ]
    },
]


class FingerprintScanner(BaseModule):
    """
    指纹识别扫描器
    识别Web应用使用的技术栈
    """
    
    name = "fingerprint_scanner"
    description = "Web应用指纹识别"
    author = "PySecScanner"
    version = "1.0.0"
    
    def __init__(self, config=None, logger=None):
        super().__init__(config, logger)
        self.timeout = 10
        self.fingerprints: List[Fingerprint] = []
        self.base_url = ""
    
    async def scan(self, target: str) -> List[ScanResult]:
        """
        执行指纹识别
        
        Args:
            target: 目标URL
        """
        self.base_url = self._normalize_url(target)
        if not self.base_url:
            self.logger.error(f"无效的URL: {target}")
            return []
        
        self.logger.info(f"目标URL: {self.base_url}")
        
        # 获取页面内容
        html, headers = await self._fetch_page()
        
        if not html:
            self.logger.warning("无法获取页面内容")
            return []
        
        # 执行指纹识别
        self.fingerprints = self._identify(html, headers)
        
        # 生成结果
        results = []
        
        # 按类别分组
        categories = {}
        for fp in self.fingerprints:
            if fp.category not in categories:
                categories[fp.category] = []
            categories[fp.category].append(fp)
        
        for category, fps in categories.items():
            fp_names = [f"{f.name} {f.version}".strip() for f in fps]
            
            result = ScanResult(
                result_type=ResultType.INFO,
                title=f"识别到 {category.upper()}: {', '.join(fp_names)}",
                description=f"检测到 {len(fps)} 个{category}相关技术",
                severity=Severity.INFO,
                target=self.base_url,
                evidence="\n".join([f"{f.name} {f.version} (置信度: {f.confidence}%)\n  证据: {f.evidence}" for f in fps]),
                raw_data={'category': category, 'fingerprints': [{'name': f.name, 'version': f.version, 'confidence': f.confidence} for f in fps]}
            )
            results.append(result)
            self.add_result(result)
        
        # 打印结果
        if self.fingerprints:
            self.logger.print_result(
                "技术栈识别",
                [f"{f.category}: {f.name} {f.version}".strip() for f in self.fingerprints]
            )
        
        return results
    
    def _normalize_url(self, url: str) -> str:
        """规范化URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url
    
    async def _fetch_page(self) -> tuple:
        """获取页面内容和响应头"""
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get(self.base_url) as response:
                    html = await response.text()
                    headers = dict(response.headers)
                    return html, headers
        except Exception as e:
            self.logger.warning(f"获取页面失败: {e}")
            return "", {}
    
    def _identify(self, html: str, headers: Dict[str, str]) -> List[Fingerprint]:
        """执行指纹识别"""
        fingerprints = []
        found_names: Set[str] = set()
        
        for rule in FINGERPRINT_RULES:
            name = rule['name']
            category = rule['category']
            
            if name in found_names:
                continue
            
            confidence = 0
            version = ""
            evidence_list = []
            
            # 检查内容模式
            if 'patterns' in rule:
                for pattern, conf in rule['patterns']:
                    match = re.search(pattern, html, re.IGNORECASE)
                    if match:
                        confidence = max(confidence, conf)
                        evidence_list.append(f"Pattern: {pattern}")
            
            # 检查响应头
            if 'headers' in rule:
                for header, pattern in rule['headers'].items():
                    header_value = headers.get(header, headers.get(header.lower(), ''))
                    if header_value:
                        match = re.search(pattern, header_value, re.IGNORECASE)
                        if match:
                            confidence = max(confidence, 90)
                            evidence_list.append(f"Header: {header}")
                            if match.groups():
                                version = match.group(1)
            
            # 提取版本
            if 'version_pattern' in rule:
                match = re.search(rule['version_pattern'], html, re.IGNORECASE)
                if match and match.groups():
                    version = match.group(1)
            
            # 添加指纹
            if confidence >= 50:
                fingerprints.append(Fingerprint(
                    name=name,
                    category=category,
                    version=version,
                    confidence=confidence,
                    evidence="; ".join(evidence_list)
                ))
                found_names.add(name)
        
        return sorted(fingerprints, key=lambda x: x.confidence, reverse=True)
    
    def get_technology_stack(self) -> Dict[str, List[str]]:
        """获取技术栈摘要"""
        stack = {}
        for fp in self.fingerprints:
            if fp.category not in stack:
                stack[fp.category] = []
            tech = f"{fp.name} {fp.version}".strip()
            stack[fp.category].append(tech)
        return stack
