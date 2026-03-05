"""
单元测试 - 核心模块
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import Config, ScanConfig
from core.base import ScanResult, Severity, ResultType
from core.logger import Logger


class TestConfig:
    """配置模块测试"""
    
    def test_config_creation(self):
        """测试配置创建"""
        config = Config()
        assert config is not None
        assert config.scan is not None
    
    def test_scan_config_defaults(self):
        """测试默认配置值"""
        config = ScanConfig()
        assert config.timeout == 10
        assert config.concurrency == 50
        assert config.verify_ssl == False
    
    def test_config_update(self):
        """测试配置更新"""
        config = Config()
        config.update(**{'scan.timeout': 20})
        assert config.scan.timeout == 20
    
    def test_config_to_dict(self):
        """测试配置转字典"""
        config = Config()
        data = config.to_dict()
        assert 'scan' in data
        assert 'port_scan' in data


class TestBaseModule:
    """模块基类测试"""
    
    def test_scan_result_creation(self):
        """测试扫描结果创建"""
        result = ScanResult(
            result_type=ResultType.PORT,
            title="Test Port",
            description="Test description",
            severity=Severity.INFO,
            target="127.0.0.1:80"
        )
        assert result.title == "Test Port"
        assert result.severity == Severity.INFO
    
    def test_scan_result_to_dict(self):
        """测试结果转字典"""
        result = ScanResult(
            result_type=ResultType.VULNERABILITY,
            title="XSS",
            severity=Severity.HIGH,
            target="http://example.com"
        )
        data = result.to_dict()
        assert data['title'] == "XSS"
        assert data['severity'] == 'high'
    
    def test_severity_enum(self):
        """测试严重程度枚举"""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"


class TestLogger:
    """日志模块测试"""
    
    def test_logger_singleton(self):
        """测试日志单例"""
        logger1 = Logger()
        logger2 = Logger()
        assert logger1 is logger2
    
    def test_logger_methods(self):
        """测试日志方法"""
        logger = Logger()
        logger.info("Test info")
        logger.warning("Test warning")
        logger.error("Test error")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
