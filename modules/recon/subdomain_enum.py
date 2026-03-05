"""
子域名枚举模块
支持字典爆破、DNS查询
"""

import asyncio
import socket
from typing import List, Optional, Set, Dict
from dataclasses import dataclass
import random

from core.base import BaseModule, ScanResult, Severity, ResultType
from core.logger import Logger


@dataclass
class SubdomainInfo:
    """子域名信息"""
    subdomain: str
    ip_addresses: List[str]
    cname: str = ""


# DNS解析器列表
DNS_RESOLVERS = [
    "8.8.8.8", "8.8.4.4",  # Google
    "1.1.1.1", "1.0.0.1",  # Cloudflare
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "114.114.114.114", "114.114.115.115",  # 114 DNS
]

# 常用子域名前缀字典
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "vpn", "admin", "portal", "ssh", "api", "dev", "test", "staging", "app",
    "blog", "shop", "store", "secure", "login", "cdn", "static", "assets",
    "img", "images", "video", "media", "files", "download", "upload",
    "m", "mobile", "wap", "forum", "bbs", "wiki", "docs", "help",
    "support", "status", "beta", "demo", "sandbox", "git", "svn",
    "jenkins", "ci", "build", "deploy", "monitor", "grafana", "prometheus",
    "db", "mysql", "postgres", "redis", "mongo", "elastic", "es",
    "internal", "intranet", "vpn", "remote", "rdp", "citrix",
    "owa", "exchange", "autodiscover", "office", "teams",
    "calendar", "contacts", "email", "imap", "pop3",
]


class SubdomainEnumerator(BaseModule):
    """
    子域名枚举器
    使用字典爆破方式发现子域名
    """
    
    name = "subdomain_enumerator"
    description = "子域名枚举工具，支持字典爆破"
    author = "PySecScanner"
    version = "1.0.0"
    
    def __init__(self, config=None, logger=None):
        super().__init__(config, logger)
        self.timeout = 3.0
        self.concurrency = 50
        self.resolvers = DNS_RESOLVERS
        self.wordlist = COMMON_SUBDOMAINS
        self.found_subdomains: List[SubdomainInfo] = []
    
    async def scan(self, target: str) -> List[ScanResult]:
        """
        执行子域名枚举
        
        Args:
            target: 目标域名
            
        Returns:
            扫描结果列表
        """
        # 验证目标
        if not self._is_valid_domain(target):
            self.logger.error(f"无效的域名: {target}")
            return []
        
        self.logger.info(f"目标域名: {target}")
        self.logger.info(f"字典大小: {len(self.wordlist)} 个子域名")
        
        # 加载自定义字典
        self._load_wordlist()
        
        # 执行枚举
        self.found_subdomains = await self._enumerate_subdomains(target)
        
        # 生成结果
        results = []
        for sub_info in self.found_subdomains:
            result = ScanResult(
                result_type=ResultType.SUBDOMAIN,
                title=f"发现子域名: {sub_info.subdomain}",
                description=f"子域名 {sub_info.subdomain} 解析到 {', '.join(sub_info.ip_addresses)}",
                severity=Severity.INFO,
                target=sub_info.subdomain,
                evidence=f"IP: {', '.join(sub_info.ip_addresses)}\nCNAME: {sub_info.cname or 'N/A'}",
                raw_data={
                    'subdomain': sub_info.subdomain,
                    'ips': sub_info.ip_addresses,
                    'cname': sub_info.cname
                }
            )
            results.append(result)
            self.add_result(result)
        
        # 打印结果
        if self.found_subdomains:
            self.logger.print_result(
                "发现的子域名",
                [f"{s.subdomain} -> {', '.join(s.ip_addresses[:2])}" 
                 for s in self.found_subdomains]
            )
        
        return results
    
    def _is_valid_domain(self, domain: str) -> bool:
        """验证域名格式"""
        import re
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
    
    def _load_wordlist(self) -> None:
        """加载自定义字典"""
        if self.config and hasattr(self.config, 'subdomain'):
            wordlist_path = self.config.subdomain.wordlist
            try:
                with open(wordlist_path, 'r', encoding='utf-8') as f:
                    custom_words = [line.strip() for line in f if line.strip()]
                    if custom_words:
                        self.wordlist = list(set(self.wordlist + custom_words))
                        self.logger.info(f"加载自定义字典: {len(custom_words)} 个条目")
            except FileNotFoundError:
                self.logger.warning(f"字典文件不存在: {wordlist_path}，使用默认字典")
    
    async def _enumerate_subdomains(self, domain: str) -> List[SubdomainInfo]:
        """枚举子域名"""
        semaphore = asyncio.Semaphore(self.concurrency)
        found: Dict[str, SubdomainInfo] = {}
        
        async def check_subdomain(sub: str) -> Optional[SubdomainInfo]:
            async with semaphore:
                full_domain = f"{sub}.{domain}"
                resolver = random.choice(self.resolvers)
                
                try:
                    # 使用自定义DNS解析器
                    loop = asyncio.get_event_loop()
                    
                    # A记录查询
                    try:
                        result = await asyncio.wait_for(
                            loop.getaddrinfo(full_domain, None),
                            timeout=self.timeout
                        )
                        ips = list(set([r[4][0] for r in result]))
                        
                        if ips:
                            # 尝试获取CNAME
                            cname = ""
                            try:
                                import dns.resolver
                                answers = dns.resolver.resolve(full_domain, 'CNAME')
                                if answers:
                                    cname = str(answers[0])
                            except:
                                pass
                            
                            return SubdomainInfo(
                                subdomain=full_domain,
                                ip_addresses=ips,
                                cname=cname
                            )
                    except socket.gaierror:
                        pass
                    except asyncio.TimeoutError:
                        pass
                        
                except Exception:
                    pass
                
                return None
        
        # 创建任务
        tasks = [check_subdomain(sub) for sub in self.wordlist]
        
        # 执行并显示进度
        completed = 0
        total = len(tasks)
        
        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed += 1
            
            if completed % 50 == 0 or completed == total:
                self.logger.print_progress(completed, total, "子域名枚举中")
            
            if result:
                found[result.subdomain] = result
        
        print()  # 换行
        
        return list(found.values())
    
    async def _dns_query(self, domain: str, record_type: str = 'A') -> List[str]:
        """DNS查询"""
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, record_type)
            return [str(r) for r in answers]
        except:
            return []
