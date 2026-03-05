"""
核心配置管理模块
支持YAML配置文件和命令行参数覆盖
"""

import os
import yaml
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from pathlib import Path


@dataclass
class ScanConfig:
    """扫描配置"""
    timeout: int = 10
    max_retries: int = 3
    concurrency: int = 50
    delay: float = 0.0
    user_agent: str = "PySecScanner/1.0"
    proxy: Optional[str] = None
    verify_ssl: bool = False


@dataclass
class PortScanConfig:
    """端口扫描配置"""
    ports: str = "1-1000"  # 支持范围和单端口，如 "1-1000" 或 "80,443,8080"
    scan_type: str = "tcp"  # tcp, syn, udp
    service_detection: bool = True
    timeout: float = 2.0


@dataclass
class SubdomainConfig:
    """子域名枚举配置"""
    wordlist: str = "data/wordlists/subdomains.txt"
    resolvers: str = "data/resolvers.txt"
    threads: int = 100
    timeout: float = 5.0


@dataclass
class DirScanConfig:
    """目录扫描配置"""
    wordlist: str = "data/wordlists/directories.txt"
    extensions: List[str] = field(default_factory=lambda: [".php", ".asp", ".aspx", ".jsp", ".html", ".js"])
    threads: int = 50
    recursive: bool = False
    max_depth: int = 2


@dataclass
class VulnScanConfig:
    """漏洞扫描配置"""
    sql_injection: bool = True
    xss: bool = True
    sensitive_info: bool = True
    headers_check: bool = True
    csrf: bool = True
    custom_payloads: str = "data/payloads"


@dataclass
class ReportConfig:
    """报告配置"""
    output_dir: str = "outputs"
    format: str = "html"  # html, json, txt
    include_evidence: bool = True
    severity_levels: List[str] = field(default_factory=lambda: ["critical", "high", "medium", "low", "info"])


class Config:
    """
    配置管理器
    支持从YAML文件加载配置，并支持运行时修改
    """
    
    DEFAULT_CONFIG_FILE = "config.yaml"
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or self.DEFAULT_CONFIG_FILE
        self.scan = ScanConfig()
        self.port_scan = PortScanConfig()
        self.subdomain = SubdomainConfig()
        self.dir_scan = DirScanConfig()
        self.vuln_scan = VulnScanConfig()
        self.report = ReportConfig()
        
        self._load_config()
    
    def _load_config(self) -> None:
        """从配置文件加载配置"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config_data = yaml.safe_load(f) or {}
                self._apply_config(config_data)
            except Exception as e:
                print(f"[!] 加载配置文件失败: {e}")
    
    def _apply_config(self, config_data: Dict[str, Any]) -> None:
        """应用配置数据到配置对象"""
        # 扫描配置
        if 'scan' in config_data:
            for key, value in config_data['scan'].items():
                if hasattr(self.scan, key):
                    setattr(self.scan, key, value)
        
        # 端口扫描配置
        if 'port_scan' in config_data:
            for key, value in config_data['port_scan'].items():
                if hasattr(self.port_scan, key):
                    setattr(self.port_scan, key, value)
        
        # 子域名配置
        if 'subdomain' in config_data:
            for key, value in config_data['subdomain'].items():
                if hasattr(self.subdomain, key):
                    setattr(self.subdomain, key, value)
        
        # 目录扫描配置
        if 'dir_scan' in config_data:
            for key, value in config_data['dir_scan'].items():
                if hasattr(self.dir_scan, key):
                    setattr(self.dir_scan, key, value)
        
        # 漏洞扫描配置
        if 'vuln_scan' in config_data:
            for key, value in config_data['vuln_scan'].items():
                if hasattr(self.vuln_scan, key):
                    setattr(self.vuln_scan, key, value)
        
        # 报告配置
        if 'report' in config_data:
            for key, value in config_data['report'].items():
                if hasattr(self.report, key):
                    setattr(self.report, key, value)
    
    def save_config(self, filepath: Optional[str] = None) -> None:
        """保存当前配置到文件"""
        filepath = filepath or self.config_file
        config_data = {
            'scan': self.scan.__dict__,
            'port_scan': self.port_scan.__dict__,
            'subdomain': self.subdomain.__dict__,
            'dir_scan': self.dir_scan.__dict__,
            'vuln_scan': self.vuln_scan.__dict__,
            'report': self.report.__dict__,
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            yaml.dump(config_data, f, default_flow_style=False, allow_unicode=True)
    
    def update(self, **kwargs) -> None:
        """动态更新配置"""
        for key, value in kwargs.items():
            parts = key.split('.')
            if len(parts) == 2:
                section, attr = parts
                if hasattr(self, section):
                    section_obj = getattr(self, section)
                    if hasattr(section_obj, attr):
                        setattr(section_obj, attr, value)
    
    def to_dict(self) -> Dict[str, Any]:
        """将配置转换为字典"""
        return {
            'scan': self.scan.__dict__,
            'port_scan': self.port_scan.__dict__,
            'subdomain': self.subdomain.__dict__,
            'dir_scan': self.dir_scan.__dict__,
            'vuln_scan': self.vuln_scan.__dict__,
            'report': self.report.__dict__,
        }
    
    def __repr__(self) -> str:
        return f"Config(scan={self.scan}, port_scan={self.port_scan}, ...)"
