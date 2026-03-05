"""
Web爬虫模块
自动爬取页面、发现参数、提取表单、分析链接
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from collections import deque

from core.base import BaseModule, ScanResult, Severity, ResultType
from core.logger import Logger


@dataclass
class LinkInfo:
    """链接信息"""
    url: str
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    form_data: Dict[str, str] = field(default_factory=dict)
    content_type: str = ""


@dataclass
class FormInfo:
    """表单信息"""
    action: str
    method: str
    inputs: List[Dict[str, str]]
    url: str


@dataclass
class PageContent:
    """页面内容"""
    url: str
    status_code: int
    content_type: str
    title: str
    links: List[str]
    forms: List[FormInfo]
    scripts: List[str]
    comments: List[str]
    meta_tags: Dict[str, str]


class WebCrawler(BaseModule):
    """
    Web爬虫模块
    自动发现页面参数和表单
    """
    
    name = "web_crawler"
    description = "Web爬虫，自动发现页面参数和表单"
    author = "PySecScanner"
    version = "1.0.0"
    
    def __init__(self, config=None, logger=None):
        super().__init__(config, logger)
        self.timeout = 10
        self.concurrency = 5
        self.max_depth = 3
        self.max_pages = 100
        self.same_domain = True
        
        self.visited: Set[str] = set()
        self.found_urls: Dict[str, LinkInfo] = {}
        self.found_forms: List[FormInfo] = []
        self.base_url = ""
        self.base_domain = ""
    
    async def scan(self, target: str) -> List[ScanResult]:
        """
        执行爬虫扫描
        
        Args:
            target: 目标URL
        """
        # 规范化URL
        self.base_url = self._normalize_url(target)
        parsed = urlparse(self.base_url)
        self.base_domain = parsed.netloc
        
        self.logger.info(f"目标URL: {self.base_url}")
        self.logger.info(f"最大深度: {self.max_depth}, 最大页面: {self.max_pages}")
        
        # 执行爬取
        await self._crawl()
        
        # 生成结果
        results = []
        
        # 发现的带参数URL
        param_urls = {url: info for url, info in self.found_urls.items() if info.params}
        if param_urls:
            result = ScanResult(
                result_type=ResultType.INFO,
                title=f"发现 {len(param_urls)} 个带参数的URL",
                description="这些URL包含查询参数，可能存在注入漏洞",
                severity=Severity.INFO,
                target=self.base_url,
                evidence="\n".join([f"{u}?{urlencode(p)}" for u, p in 
                                   [(u, i.params) for u, i in param_urls.items()][:10]]),
                raw_data={'param_urls': list(param_urls.keys())}
            )
            results.append(result)
        
        # 发现的表单
        if self.found_forms:
            result = ScanResult(
                result_type=ResultType.INFO,
                title=f"发现 {len(self.found_forms)} 个表单",
                description="这些表单可能存在注入漏洞",
                severity=Severity.INFO,
                target=self.base_url,
                evidence="\n".join([
                    f"[{f.method}] {f.action} - {len(f.inputs)} 个输入字段" 
                    for f in self.found_forms[:10]
                ]),
                raw_data={'forms': [{'action': f.action, 'method': f.method, 
                                    'inputs': f.inputs} for f in self.found_forms]}
            )
            results.append(result)
        
        # 打印结果
        self.logger.print_result(
            "爬取统计",
            [
                f"访问页面: {len(self.visited)}",
                f"发现URL: {len(self.found_urls)}",
                f"带参数URL: {len(param_urls)}",
                f"发现表单: {len(self.found_forms)}"
            ]
        )
        
        return results
    
    def _normalize_url(self, url: str) -> str:
        """规范化URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        # 移除fragment
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path or '/',
            parsed.params,
            parsed.query,
            ''
        ))
    
    def _is_same_domain(self, url: str) -> bool:
        """检查是否同域名"""
        if not self.same_domain:
            return True
        
        parsed = urlparse(url)
        return parsed.netloc == self.base_domain
    
    def _should_visit(self, url: str) -> bool:
        """判断是否应该访问该URL"""
        # 已访问过
        if url in self.visited:
            return False
        
        # 非HTTP(S)
        if not url.startswith(('http://', 'https://')):
            return False
        
        # 非同域名
        if not self._is_same_domain(url):
            return False
        
        # 过滤静态资源
        skip_extensions = {'.css', '.js', '.jpg', '.jpeg', '.png', '.gif', 
                          '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot',
                          '.pdf', '.zip', '.tar', '.gz', '.mp3', '.mp4', '.avi'}
        
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        for ext in skip_extensions:
            if path.endswith(ext):
                return False
        
        return True
    
    async def _crawl(self) -> None:
        """执行爬取"""
        queue = deque([(self.base_url, 0)])  # (url, depth)
        
        connector = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            while queue and len(self.visited) < self.max_pages:
                url, depth = queue.popleft()
                
                if depth > self.max_depth:
                    continue
                
                if not self._should_visit(url):
                    continue
                
                self.visited.add(url)
                
                try:
                    page_content = await self._fetch_page(session, url)
                    
                    if page_content:
                        # 提取链接
                        for link in page_content.links:
                            absolute_url = urljoin(url, link)
                            normalized = self._normalize_url(absolute_url)
                            
                            # 记录URL
                            parsed = urlparse(normalized)
                            params = parse_qs(parsed.query)
                            params = {k: v[0] if v else '' for k, v in params.items()}
                            
                            self.found_urls[normalized] = LinkInfo(
                                url=normalized,
                                params=params
                            )
                            
                            # 加入队列
                            if self._should_visit(normalized):
                                queue.append((normalized, depth + 1))
                        
                        # 提取表单
                        for form in page_content.forms:
                            self.found_forms.append(form)
                            
                            # 表单action URL
                            form_url = urljoin(url, form.action)
                            if self._should_visit(form_url):
                                queue.append((form_url, depth + 1))
                        
                        # 显示进度
                        self.logger.print_progress(
                            len(self.visited), 
                            min(self.max_pages, len(self.visited) + len(queue)),
                            f"爬取: {url[:50]}..."
                        )
                        
                except Exception as e:
                    self.logger.debug(f"爬取失败 {url}: {e}")
        
        print()
    
    async def _fetch_page(self, session: aiohttp.ClientSession, url: str) -> Optional[PageContent]:
        """获取页面内容"""
        try:
            async with session.get(url) as response:
                if response.status != 200:
                    return None
                
                content_type = response.headers.get('Content-Type', '')
                
                # 只处理HTML页面
                if 'text/html' not in content_type:
                    return None
                
                html = await response.text()
                
                return self._parse_html(url, html, content_type)
                
        except Exception as e:
            return None
    
    def _parse_html(self, url: str, html: str, content_type: str) -> PageContent:
        """解析HTML内容"""
        # 提取标题
        title = ""
        title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()
        
        # 提取链接
        links = set()
        for match in re.finditer(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE):
            links.add(match.group(1))
        for match in re.finditer(r'src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            links.add(match.group(1))
        
        # 提取表单
        forms = []
        form_pattern = re.compile(
            r'<form[^>]*action=["\']?([^"\'>\s]+)["\']?[^>]*method=["\']?([^"\'>\s]*)["\']?[^>]*>(.*?)</form>',
            re.IGNORECASE | re.DOTALL
        )
        
        for match in form_pattern.finditer(html):
            action = match.group(1) or url
            method = match.group(2).upper() or 'GET'
            form_html = match.group(3)
            
            # 提取输入字段
            inputs = []
            input_pattern = re.compile(
                r'<input[^>]*name=["\']?([^"\'>\s]+)["\']?[^>]*type=["\']?([^"\'>\s]*)["\']?[^>]*value=["\']?([^"\'>\s]*)["\']?',
                re.IGNORECASE
            )
            
            for input_match in input_pattern.finditer(form_html):
                inputs.append({
                    'name': input_match.group(1),
                    'type': input_match.group(2) or 'text',
                    'value': input_match.group(3) or ''
                })
            
            # 提取textarea
            textarea_pattern = re.compile(
                r'<textarea[^>]*name=["\']?([^"\'>\s]+)["\']?[^>]*>',
                re.IGNORECASE
            )
            for textarea_match in textarea_pattern.finditer(form_html):
                inputs.append({
                    'name': textarea_match.group(1),
                    'type': 'textarea',
                    'value': ''
                })
            
            # 提取select
            select_pattern = re.compile(
                r'<select[^>]*name=["\']?([^"\'>\s]+)["\']?[^>]*>',
                re.IGNORECASE
            )
            for select_match in select_pattern.finditer(form_html):
                inputs.append({
                    'name': select_match.group(1),
                    'type': 'select',
                    'value': ''
                })
            
            forms.append(FormInfo(
                action=action,
                method=method,
                inputs=inputs,
                url=url
            ))
        
        # 提取脚本
        scripts = []
        for match in re.finditer(r'<script[^>]*src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            scripts.append(match.group(1))
        
        # 提取注释
        comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        
        # 提取meta标签
        meta_tags = {}
        for match in re.finditer(r'<meta[^>]*name=["\']([^"\']+)["\'][^>]*content=["\']([^"\']+)["\']', html, re.IGNORECASE):
            meta_tags[match.group(1)] = match.group(2)
        
        return PageContent(
            url=url,
            status_code=200,
            content_type=content_type,
            title=title,
            links=list(links),
            forms=forms,
            scripts=scripts,
            comments=comments,
            meta_tags=meta_tags
        )
    
    def get_param_urls(self) -> Dict[str, Dict[str, str]]:
        """获取所有带参数的URL"""
        return {url: info.params for url, info in self.found_urls.items() if info.params}
    
    def get_forms(self) -> List[FormInfo]:
        """获取所有表单"""
        return self.found_forms
