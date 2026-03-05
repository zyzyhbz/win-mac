"""
工具函数模块
"""

import re
import socket
import asyncio
from typing import Optional, List, Tuple
from urllib.parse import urlparse


def is_valid_ip(ip: str) -> bool:
    """验证IP地址格式"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    return False


def is_valid_domain(domain: str) -> bool:
    """验证域名格式"""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def is_valid_url(url: str) -> bool:
    """验证URL格式"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def normalize_url(url: str) -> str:
    """规范化URL"""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url


async def resolve_host(host: str) -> Optional[str]:
    """解析主机名为IP地址"""
    try:
        loop = asyncio.get_event_loop()
        result = await loop.getaddrinfo(host, None)
        if result:
            return result[0][4][0]
    except:
        pass
    return None


def parse_port_range(port_spec: str) -> List[int]:
    """
    解析端口范围
    
    支持格式:
    - "80" - 单个端口
    - "80,443,8080" - 多个端口
    - "1-1000" - 端口范围
    - "1-100,443,8080-8090" - 混合格式
    """
    ports = set()
    
    for part in port_spec.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    
    return sorted(ports)


def get_common_ports() -> List[int]:
    """获取常用端口列表"""
    return [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
        993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379,
        8080, 8443, 9000, 9200, 27017
    ]


def extract_domain(url: str) -> str:
    """从URL中提取域名"""
    parsed = urlparse(url)
    return parsed.netloc.split(':')[0]


def extract_parameters(url: str) -> dict:
    """从URL中提取参数"""
    from urllib.parse import parse_qs, urlparse
    
    parsed = urlparse(url)
    params = {}
    
    if parsed.query:
        query_params = parse_qs(parsed.query)
        for key, values in query_params.items():
            params[key] = values[0] if values else ""
    
    return params


def build_url(base: str, params: dict) -> str:
    """构建URL"""
    from urllib.parse import urlencode, urlparse, urlunparse
    
    parsed = urlparse(base)
    query = urlencode(params)
    
    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        query,
        parsed.fragment
    ))


def truncate_string(s: str, max_length: int = 100) -> str:
    """截断字符串"""
    if len(s) <= max_length:
        return s
    return s[:max_length - 3] + "..."


def clean_html(html: str) -> str:
    """清理HTML标签"""
    clean = re.compile('<.*?>')
    return re.sub(clean, '', html)


def extract_title(html: str) -> str:
    """从HTML中提取标题"""
    match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()[:100]
    return ""
