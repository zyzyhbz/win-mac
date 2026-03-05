"""
敏感信息泄露检测模块
检测页面中的敏感信息、配置文件泄露等
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

from core.base import BaseModule, ScanResult, Severity, ResultType
from core.logger import Logger


@dataclass
class SensitiveInfo:
    """敏感信息"""
    info_type: str
    content: str
    location: str
    severity: Severity
    description: str


# 敏感信息正则模式
SENSITIVE_PATTERNS = [
    # API密钥和Token
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}", Severity.HIGH),
    ("AWS Secret Key", r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+=]{40}['\"]", Severity.HIGH),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", Severity.HIGH),
    ("Google OAuth", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", Severity.HIGH),
    ("GitHub Token", r"ghp_[0-9a-zA-Z]{36}", Severity.HIGH),
    ("GitHub OAuth", r"gho_[0-9a-zA-Z]{36}", Severity.HIGH),
    ("Slack Token", r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}", Severity.HIGH),
    ("Stripe API Key", r"sk_live_[0-9a-zA-Z]{24}", Severity.HIGH),
    ("Twilio Account SID", r"AC[a-f0-9]{32}", Severity.MEDIUM),
    ("Twilio Auth Token", r"[a-f0-9]{32}", Severity.MEDIUM),
    
    # 数据库连接字符串
    ("MySQL Connection", r"mysql://[^:]+:[^@]+@[^/]+/[^\s'\"]+", Severity.HIGH),
    ("PostgreSQL Connection", r"postgres(ql)?://[^:]+:[^@]+@[^/]+/[^\s'\"]+", Severity.HIGH),
    ("MongoDB Connection", r"mongodb(\+srv)?://[^:]+:[^@]+@[^\s'\"]+", Severity.HIGH),
    ("Redis Connection", r"redis://[^:]*:[^@]+@[^/]+", Severity.HIGH),
    
    # 密码和凭证
    ("Password in Code", r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]", Severity.HIGH),
    ("API Secret", r"(?i)(api[_-]?key|secret|token)\s*[=:]\s*['\"][^'\"]{8,}['\"]", Severity.MEDIUM),
    ("Private Key", r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", Severity.CRITICAL),
    ("SSH Key", r"ssh-rsa AAAA[0-9A-Za-z+/]+[=]{0,3}", Severity.HIGH),
    
    # 敏感文件路径
    ("Config File Path", r"(?i)['\"]?(/[a-zA-Z0-9_\-./]+)?(config|settings|database)\.(php|ini|json|yml|yaml|xml|conf)['\"]?", Severity.LOW),
    ("Backup File", r"(?i)['\"]?(/[a-zA-Z0-9_\-./]+)?\.(bak|backup|old|orig|save)['\"]?", Severity.LOW),
    
    # 内部IP和域名
    ("Internal IP", r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", Severity.LOW),
    ("Localhost Reference", r"localhost|127\.0\.0\.1|0\.0\.0\.0", Severity.INFO),
    
    # 邮箱地址
    ("Email Address", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", Severity.INFO),
    
    # 手机号（中国）
    ("Phone Number (CN)", r"(?:\+?86)?1[3-9]\d{9}", Severity.INFO),
    
    # 身份证号（中国）
    ("ID Card (CN)", r"\b[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b", Severity.MEDIUM),
    
    # 银行卡号
    ("Bank Card", r"\b(?:62|4|5)\d{14,17}\b", Severity.MEDIUM),
    
    # JWT Token
    ("JWT Token", r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+", Severity.MEDIUM),
    
    # 调试信息
    ("Debug Info", r"(?i)(debug|stack\s*trace|error\s*report|exception)\s*[:=]", Severity.LOW),
    ("PHP Error", r"(?i)(fatal error|parse error|warning|notice)\s*:.+in\s+.+\.php", Severity.LOW),
    ("SQL Error", r"(?i)(sql|mysql|oracle|postgres).*error.*:", Severity.MEDIUM),
    
    # 版本信息
    ("Version Disclosure", r"(?i)(version|v)\s*[=:]\s*['\"]?\d+\.\d+\.?\d*['\"]?", Severity.INFO),
    ("Server Header", r"(?i)(server|powered-by)\s*:\s*[^\r\n]+", Severity.INFO),
]

# 敏感文件路径
SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/.htaccess",
    "/.htpasswd",
    "/web.config",
    "/config.php",
    "/configuration.php",
    "/settings.php",
    "/database.yml",
    "/config/database.yml",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/debug.php",
    "/server-status",
    "/server-info",
    "/robots.txt",
    "/sitemap.xml",
    "/.DS_Store",
    "/backup.sql",
    "/backup.zip",
    "/dump.sql",
    "/.backup/",
    "/admin/",
    "/phpmyadmin/",
    "/adminer.php",
]


class SensitiveInfoScanner(BaseModule):
    """
    敏感信息泄露扫描器
    检测页面内容和敏感文件泄露
    """
    
    name = "sensitive_info_scanner"
    description = "敏感信息泄露检测器"
    author = "PySecScanner"
    version = "1.0.0"
    
    def __init__(self, config=None, logger=None):
        super().__init__(config, logger)
        self.timeout = 10
        self.concurrency = 10
        self.patterns = SENSITIVE_PATTERNS
        self.sensitive_paths = SENSITIVE_PATHS
        self.findings: List[SensitiveInfo] = []
        self.base_url = ""
    
    async def scan(self, target: str) -> List[ScanResult]:
        """
        执行敏感信息扫描
        
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
        
        # 扫描主页内容
        self.logger.info("扫描页面内容...")
        content_findings = await self._scan_content(self.base_url)
        self.findings.extend(content_findings)
        
        # 扫描敏感文件
        self.logger.info("扫描敏感文件...")
        file_findings = await self._scan_sensitive_files()
        self.findings.extend(file_findings)
        
        # 生成结果
        results = []
        for finding in self.findings:
            result = ScanResult(
                result_type=ResultType.INFO,
                title=f"敏感信息: {finding.info_type}",
                description=finding.description,
                severity=finding.severity,
                target=finding.location,
                evidence=f"类型: {finding.info_type}\n内容: {finding.content[:100]}...",
                raw_data={
                    'type': finding.info_type,
                    'content': finding.content,
                    'location': finding.location
                }
            )
            results.append(result)
            self.add_result(result)
        
        # 打印结果
        if self.findings:
            self.logger.print_result(
                "发现的敏感信息",
                [f"[{f.severity.value.upper()}] {f.info_type}" for f in self.findings]
            )
        else:
            self.logger.info("未发现敏感信息泄露")
        
        return results
    
    def _normalize_url(self, url: str) -> str:
        """规范化URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')
    
    async def _scan_content(self, url: str) -> List[SensitiveInfo]:
        """扫描页面内容"""
        findings = []
        
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get(url) as response:
                    content = await response.text()
                    
                    # 检查每个模式
                    for info_type, pattern, severity in self.patterns:
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            matched_content = match.group(0)
                            # 避免重复
                            if not any(f.content == matched_content for f in findings):
                                findings.append(SensitiveInfo(
                                    info_type=info_type,
                                    content=matched_content,
                                    location=url,
                                    severity=severity,
                                    description=f"在页面中发现{info_type}"
                                ))
                                self.logger.highlight(f"发现: {info_type}")
                                
        except Exception as e:
            self.logger.warning(f"扫描内容失败: {e}")
        
        return findings
    
    async def _scan_sensitive_files(self) -> List[SensitiveInfo]:
        """扫描敏感文件"""
        semaphore = asyncio.Semaphore(self.concurrency)
        findings = []
        
        connector = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async def check_path(path: str) -> Optional[SensitiveInfo]:
            async with semaphore:
                url = self.base_url + path
                
                try:
                    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                        async with session.get(url, allow_redirects=False) as response:
                            if response.status == 200:
                                content = await response.text()
                                content_length = len(content)
                                
                                # 检查是否是有效内容（不是404页面）
                                if content_length > 0 and "not found" not in content.lower():
                                    return SensitiveInfo(
                                        info_type=f"敏感文件: {path}",
                                        content=f"文件可访问，大小: {content_length} bytes",
                                        location=url,
                                        severity=Severity.MEDIUM,
                                        description=f"敏感文件 {path} 可直接访问"
                                    )
                                    
                except Exception:
                    pass
                
                return None
        
        # 创建任务
        tasks = [check_path(path) for path in self.sensitive_paths]
        
        # 执行
        completed = 0
        total = len(tasks)
        
        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed += 1
            self.logger.print_progress(completed, total, "敏感文件扫描中")
            
            if result:
                findings.append(result)
                self.logger.highlight(f"发现: {result.info_type}")
        
        print()
        
        return findings
