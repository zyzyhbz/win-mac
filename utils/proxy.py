"""
代理支持模块
支持HTTP/SOCKS5代理和代理池
"""

import asyncio
import random
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import aiohttp


class ProxyType(Enum):
    HTTP = "http"
    HTTPS = "https"
    SOCKS5 = "socks5"


@dataclass
class ProxyInfo:
    """代理信息"""
    host: str
    port: int
    proxy_type: ProxyType
    username: str = ""
    password: str = ""
    is_alive: bool = True
    latency: float = 0.0
    last_check: float = 0.0
    
    def to_url(self) -> str:
        """转换为代理URL"""
        if self.username and self.password:
            auth = f"{self.username}:{self.password}@"
        else:
            auth = ""
        
        scheme = self.proxy_type.value
        return f"{scheme}://{auth}{self.host}:{self.port}"


class ProxyManager:
    """
    代理管理器
    支持单代理和代理池
    """
    
    def __init__(self, proxies: List[str] = None, proxy_file: str = None):
        """
        初始化代理管理器
        
        Args:
            proxies: 代理列表，格式如 ["http://1.2.3.4:8080", "socks5://user:pass@5.6.7.8:1080"]
            proxy_file: 代理文件路径，每行一个代理
        """
        self.proxies: List[ProxyInfo] = []
        self.current_index = 0
        self.enabled = False
        
        # 加载代理
        if proxies:
            self._load_from_list(proxies)
        
        if proxy_file:
            self._load_from_file(proxy_file)
        
        if self.proxies:
            self.enabled = True
    
    def _load_from_list(self, proxies: List[str]) -> None:
        """从列表加载代理"""
        for proxy in proxies:
            proxy_info = self._parse_proxy(proxy)
            if proxy_info:
                self.proxies.append(proxy_info)
    
    def _load_from_file(self, filepath: str) -> None:
        """从文件加载代理"""
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        proxy_info = self._parse_proxy(line)
                        if proxy_info:
                            self.proxies.append(proxy_info)
        except FileNotFoundError:
            pass
    
    def _parse_proxy(self, proxy_str: str) -> Optional[ProxyInfo]:
        """解析代理字符串"""
        try:
            # 格式: [scheme://][user:pass@]host:port
            scheme = "http"
            
            if "://" in proxy_str:
                scheme, proxy_str = proxy_str.split("://", 1)
            
            # 解析认证信息
            auth = ""
            if "@" in proxy_str:
                auth, proxy_str = proxy_str.rsplit("@", 1)
            
            # 解析主机和端口
            if ":" in proxy_str:
                host, port = proxy_str.rsplit(":", 1)
                port = int(port)
            else:
                return None
            
            # 解析用户名密码
            username, password = "", ""
            if auth:
                if ":" in auth:
                    username, password = auth.split(":", 1)
                else:
                    username = auth
            
            # 确定代理类型
            proxy_type = ProxyType.HTTP
            if scheme.lower() == "socks5":
                proxy_type = ProxyType.SOCKS5
            elif scheme.lower() == "https":
                proxy_type = ProxyType.HTTPS
            
            return ProxyInfo(
                host=host,
                port=port,
                proxy_type=proxy_type,
                username=username,
                password=password
            )
            
        except Exception:
            return None
    
    def get_proxy(self) -> Optional[ProxyInfo]:
        """获取一个代理（轮询方式）"""
        if not self.proxies:
            return None
        
        proxy = self.proxies[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.proxies)
        return proxy
    
    def get_random_proxy(self) -> Optional[ProxyInfo]:
        """随机获取一个代理"""
        if not self.proxies:
            return None
        return random.choice(self.proxies)
    
    def get_proxy_url(self) -> Optional[str]:
        """获取代理URL"""
        proxy = self.get_proxy()
        return proxy.to_url() if proxy else None
    
    async def check_proxy(self, proxy: ProxyInfo, test_url: str = "http://httpbin.org/ip", 
                          timeout: float = 10.0) -> bool:
        """检查代理是否可用"""
        try:
            connector = None
            
            if proxy.proxy_type == ProxyType.SOCKS5:
                # SOCKS5需要额外支持
                try:
                    from aiohttp_socks import ProxyConnector
                    connector = ProxyConnector.from_url(proxy.to_url())
                except ImportError:
                    return False
            else:
                connector = aiohttp.TCPConnector()
            
            timeout_obj = aiohttp.ClientTimeout(total=timeout)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout_obj) as session:
                async with session.get(test_url, proxy=proxy.to_url() if proxy.proxy_type != ProxyType.SOCKS5 else None) as resp:
                    if resp.status == 200:
                        proxy.is_alive = True
                        return True
            
        except Exception:
            proxy.is_alive = False
        
        return False
    
    async def check_all_proxies(self, timeout: float = 10.0) -> int:
        """检查所有代理，返回可用数量"""
        tasks = [self.check_proxy(p, timeout=timeout) for p in self.proxies]
        results = await asyncio.gather(*tasks)
        return sum(results)
    
    def remove_dead_proxies(self) -> int:
        """移除不可用代理，返回移除数量"""
        original_count = len(self.proxies)
        self.proxies = [p for p in self.proxies if p.is_alive]
        return original_count - len(self.proxies)
    
    def add_proxy(self, proxy_str: str) -> bool:
        """添加代理"""
        proxy_info = self._parse_proxy(proxy_str)
        if proxy_info:
            self.proxies.append(proxy_info)
            self.enabled = True
            return True
        return False
    
    def get_stats(self) -> Dict:
        """获取代理统计信息"""
        alive_count = sum(1 for p in self.proxies if p.is_alive)
        return {
            "total": len(self.proxies),
            "alive": alive_count,
            "dead": len(self.proxies) - alive_count,
            "enabled": self.enabled
        }


def create_proxy_session(proxy: str = None, proxy_manager: ProxyManager = None) -> aiohttp.ClientSession:
    """
    创建支持代理的aiohttp会话
    
    Args:
        proxy: 单个代理URL
        proxy_manager: 代理管理器实例
        
    Returns:
        配置好代理的ClientSession
    """
    connector = None
    proxy_url = None
    
    if proxy:
        proxy_url = proxy
    elif proxy_manager and proxy_manager.enabled:
        proxy_url = proxy_manager.get_proxy_url()
    
    if proxy_url and proxy_url.startswith("socks5://"):
        try:
            from aiohttp_socks import ProxyConnector
            connector = ProxyConnector.from_url(proxy_url)
            proxy_url = None  # SOCKS5通过connector处理
        except ImportError:
            pass
    
    return aiohttp.ClientSession(connector=connector), proxy_url


# 便捷函数
def setup_proxy(proxy_str: str = None, proxy_file: str = None) -> ProxyManager:
    """
    设置代理
    
    Args:
        proxy_str: 单个代理，如 "http://127.0.0.1:8080"
        proxy_file: 代理文件路径
        
    Returns:
        ProxyManager实例
    """
    proxies = [proxy_str] if proxy_str else None
    return ProxyManager(proxies=proxies, proxy_file=proxy_file)
