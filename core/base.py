"""
模块基类
定义所有扫描模块的通用接口和行为
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import time

from core.logger import logger as global_logger

class Severity(Enum):
    """漏洞严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ResultType(Enum):
    """结果类型"""
    PORT = "port"
    SUBDOMAIN = "subdomain"
    DIRECTORY = "directory"
    VULNERABILITY = "vulnerability"
    INFO = "info"
    SERVICE = "service"


@dataclass
class ScanResult:
    """扫描结果数据类"""
    result_type: ResultType
    title: str
    description: str = ""
    severity: Severity = Severity.INFO
    target: str = ""
    evidence: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'result_type': self.result_type.value,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'target': self.target,
            'evidence': self.evidence,
            'raw_data': self.raw_data,
            'timestamp': self.timestamp
        }


class BaseModule(ABC):
    """
    扫描模块基类
    所有扫描模块必须继承此类并实现相应方法
    """
    
    # 模块元信息
    name: str = "base_module"
    description: str = "基础模块"
    author: str = ""
    version: str = "1.0.0"
    
    def __init__(self, config: Any = None, logger: Any = None):
        """
        初始化模块
        
        Args:
            config: 配置对象
            logger: 日志对象；如果不提供则使用全局日志实例
        """
        self.config = config
        # 默认使用全局 logger，避免子类未显式传入时为 None
        self.logger = logger or global_logger
        self.results: List[ScanResult] = []
        self._start_time: float = 0
        self._end_time: float = 0
    
    @abstractmethod
    async def scan(self, target: str) -> List[ScanResult]:
        """
        执行扫描（抽象方法，子类必须实现）
        
        Args:
            target: 扫描目标
            
        Returns:
            扫描结果列表
        """
        pass
    
    def pre_scan(self, target: str) -> bool:
        """
        扫描前准备工作
        
        Args:
            target: 扫描目标
            
        Returns:
            是否准备成功
        """
        self._start_time = time.time()
        self.results.clear()
        return True
    
    def post_scan(self) -> None:
        """扫描后清理工作"""
        self._end_time = time.time()
    
    def add_result(self, result: ScanResult) -> None:
        """添加扫描结果"""
        self.results.append(result)
    
    def get_results(self) -> List[ScanResult]:
        """获取所有扫描结果"""
        return self.results
    
    def get_duration(self) -> float:
        """获取扫描耗时"""
        if self._end_time > 0:
            return self._end_time - self._start_time
        return time.time() - self._start_time
    
    def get_stats(self) -> Dict[str, Any]:
        """获取扫描统计信息"""
        severity_count = {}
        for result in self.results:
            sev = result.severity.value
            severity_count[sev] = severity_count.get(sev, 0) + 1
        
        return {
            'module': self.name,
            'total_results': len(self.results),
            'duration': self.get_duration(),
            'severity_distribution': severity_count
        }
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self.name} v{self.version}>"
