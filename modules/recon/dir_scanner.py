"""
目录扫描模块
支持字典爆破、状态码过滤
"""

import asyncio
import aiohttp
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from core.base import BaseModule, ScanResult, Severity, ResultType
from core.logger import Logger


@dataclass
class DirectoryInfo:
    """目录信息"""
    path: str
    url: str
    status_code: int
    content_length: int
    content_type: str = ""
    redirect_url: str = ""
    title: str = ""


# 常见目录字典
COMMON_DIRECTORIES = [
    "admin", "administrator", "admin.php", "admin.html", "wp-admin", "phpmyadmin",
    "login", "signin", "register", "signup", "logout", "account",
    "api", "api/v1", "api/v2", "graphql", "rest",
    "backup", "backups", "old", "new", "bak", "backup.zip", "backup.sql",
    "config", "conf", "configuration.php", "config.php", "settings.php",
    "data", "db", "database", "sql", "dump", "export",
    "upload", "uploads", "files", "download", "downloads", "attachments",
    "images", "img", "static", "assets", "css", "js", "fonts", "lib",
    "test", "tests", "testing", "debug", "dev", "development", "staging",
    "docs", "documentation", "readme", "changelog", "license",
    "logs", "log", "tmp", "temp", "cache", "session",
    "user", "users", "member", "members", "profile", "profiles",
    "search", "find", "query", "browse", "list",
    "dashboard", "panel", "control", "manage", "management",
    "console", "terminal", "shell", "cmd", "exec", "run",
    ".git", ".svn", ".env", ".htaccess", ".htpasswd", ".DS_Store",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "security.txt",
    "web.config", "server-status", "server-info", "elmah.axd",
    "index.php", "index.html", "index.asp", "index.aspx", "index.jsp",
    "info.php", "phpinfo.php", "test.php", "shell.php", "cmd.php",
    "xmlrpc.php", "wp-config.php", "wp-content", "wp-includes",
    "cgi-bin", "scripts", "includes", "inc", "modules", "plugins",
    "vendor", "node_modules", "bower_components", "package.json", "composer.json",
]


# 默认忽略的状态码
IGNORE_STATUS_CODES = {404}


# 关注的状态码
INTERESTING_STATUS_CODES = {200, 301, 302, 303, 307, 308, 401, 403, 500}


class DirScanner(BaseModule):
    """
    目录扫描器
    使用字典爆破方式发现隐藏目录和文件
    """
    
    name = "dir_scanner"
    description = "目录和文件扫描器，支持字典爆破"
    author = "PySecScanner"
    version = "1.0.0"
    
    def __init__(self, config=None, logger=None):
        super().__init__(config, logger)
        self.timeout = 10
        self.concurrency = 20
        self.wordlist = COMMON_DIRECTORIES
        self.extensions = [".php", ".html", ".asp", ".aspx", ".jsp", ".js", ".json", ".xml", ".txt", ".bak"]
        self.found_paths: List[DirectoryInfo] = []
        self.base_url = ""
    
    async def scan(self, target: str) -> List[ScanResult]:
        """
        执行目录扫描
        
        Args:
            target: 目标URL
            
        Returns:
            扫描结果列表
        """
        # 验证并规范化URL
        self.base_url = self._normalize_url(target)
        if not self.base_url:
            self.logger.error(f"无效的URL: {target}")
            return []
        
        self.logger.info(f"目标URL: {self.base_url}")
        
        # 加载自定义字典
        self._load_wordlist()
        
        # 生成扫描路径
        paths = self._generate_paths()
        self.logger.info(f"扫描路径: {len(paths)} 个")
        
        # 执行扫描
        self.found_paths = await self._scan_paths(paths)
        
        # 生成结果
        results = []
        for dir_info in self.found_paths:
            severity = self._get_severity(dir_info.status_code)
            
            result = ScanResult(
                result_type=ResultType.DIRECTORY,
                title=f"发现路径: {dir_info.path} [{dir_info.status_code}]",
                description=f"路径 {dir_info.path} 返回状态码 {dir_info.status_code}",
                severity=severity,
                target=dir_info.url,
                evidence=f"状态码: {dir_info.status_code}\n大小: {dir_info.content_length} bytes\n类型: {dir_info.content_type}\n重定向: {dir_info.redirect_url or 'N/A'}",
                raw_data=dir_info.__dict__
            )
            results.append(result)
            self.add_result(result)
        
        # 打印结果
        if self.found_paths:
            self.logger.print_result(
                "发现的路径",
                [f"[{d.status_code}] {d.path} ({d.content_length} bytes)" 
                 for d in self.found_paths]
            )
        
        return results
    
    def _normalize_url(self, url: str) -> str:
        """规范化URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        if not parsed.netloc:
            return ""
        
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def _load_wordlist(self) -> None:
        """加载自定义字典"""
        if self.config and hasattr(self.config, 'dir_scan'):
            wordlist_path = self.config.dir_scan.wordlist
            try:
                with open(wordlist_path, 'r', encoding='utf-8') as f:
                    custom_paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    if custom_paths:
                        self.wordlist = list(set(self.wordlist + custom_paths))
                        self.logger.info(f"加载自定义字典: {len(custom_paths)} 个条目")
            except FileNotFoundError:
                self.logger.warning(f"字典文件不存在: {wordlist_path}，使用默认字典")
            
            # 加载扩展名
            if self.config.dir_scan.extensions:
                self.extensions = self.config.dir_scan.extensions
    
    def _generate_paths(self) -> List[str]:
        """生成扫描路径列表"""
        paths = set()
        
        for word in self.wordlist:
            # 原始路径
            paths.add(word)
            
            # 添加扩展名（仅对非文件路径）
            if '.' not in word.split('/')[-1]:
                for ext in self.extensions:
                    paths.add(f"{word}{ext}")
        
        return list(paths)
    
    async def _scan_paths(self, paths: List[str]) -> List[DirectoryInfo]:
        """扫描路径"""
        semaphore = asyncio.Semaphore(self.concurrency)
        found: List[DirectoryInfo] = []
        
        connector = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async def check_path(path: str) -> Optional[DirectoryInfo]:
            async with semaphore:
                url = urljoin(self.base_url, path)
                
                try:
                    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                        async with session.get(url, allow_redirects=False) as response:
                            if response.status in IGNORE_STATUS_CODES:
                                return None
                            
                            if response.status in INTERESTING_STATUS_CODES:
                                content_length = int(response.headers.get('Content-Length', 0))
                                content_type = response.headers.get('Content-Type', '')
                                redirect_url = response.headers.get('Location', '')
                                
                                # 获取页面标题
                                title = ""
                                if 'text/html' in content_type:
                                    try:
                                        text = await response.text()
                                        import re
                                        match = re.search(r'<title>(.*?)</title>', text, re.IGNORECASE | re.DOTALL)
                                        if match:
                                            title = match.group(1).strip()[:50]
                                    except:
                                        pass
                                
                                return DirectoryInfo(
                                    path=path,
                                    url=url,
                                    status_code=response.status,
                                    content_length=content_length,
                                    content_type=content_type,
                                    redirect_url=redirect_url,
                                    title=title
                                )
                                
                except asyncio.TimeoutError:
                    pass
                except aiohttp.ClientError:
                    pass
                except Exception:
                    pass
                
                return None
        
        # 创建任务
        tasks = [check_path(path) for path in paths]
        
        # 执行并显示进度
        completed = 0
        total = len(tasks)
        
        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed += 1
            
            if completed % 20 == 0 or completed == total:
                self.logger.print_progress(completed, total, "目录扫描中")
            
            if result:
                found.append(result)
                # 实时显示发现
                self.logger.success(f"发现: {result.path} [{result.status_code}]")
        
        print()  # 换行
        
        return sorted(found, key=lambda x: x.path)
    
    def _get_severity(self, status_code: int) -> Severity:
        """根据状态码判断严重程度"""
        if status_code == 200:
            return Severity.LOW
        elif status_code in {401, 403}:
            return Severity.MEDIUM
        elif status_code in {500, 502, 503}:
            return Severity.INFO
        else:
            return Severity.INFO
