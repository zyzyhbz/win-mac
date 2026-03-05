"""
单元测试 - 工具函数
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.helpers import (
    is_valid_ip, is_valid_domain, is_valid_url,
    normalize_url, parse_port_range, get_common_ports,
    extract_domain, extract_parameters, build_url
)


class TestValidators:
    """验证函数测试"""
    
    def test_valid_ip(self):
        """测试IP验证"""
        assert is_valid_ip("192.168.1.1") == True
        assert is_valid_ip("10.0.0.1") == True
        assert is_valid_ip("255.255.255.255") == True
        assert is_valid_ip("999.999.999.999") == False
        assert is_valid_ip("not.an.ip") == False
        assert is_valid_ip("") == False
    
    def test_valid_domain(self):
        """测试域名验证"""
        assert is_valid_domain("example.com") == True
        assert is_valid_domain("sub.example.com") == True
        assert is_valid_domain("test-site.org") == True
        assert is_valid_domain("invalid") == False
        assert is_valid_domain("") == False
    
    def test_valid_url(self):
        """测试URL验证"""
        assert is_valid_url("http://example.com") == True
        assert is_valid_url("https://example.com/path") == True
        assert is_valid_url("ftp://ftp.example.com") == True
        assert is_valid_url("not-a-url") == False
    
    def test_normalize_url(self):
        """测试URL规范化"""
        assert normalize_url("example.com") == "http://example.com"
        assert normalize_url("https://example.com") == "https://example.com"


class TestPortParser:
    """端口解析测试"""
    
    def test_single_port(self):
        """测试单个端口"""
        ports = parse_port_range("80")
        assert ports == [80]
    
    def test_port_range(self):
        """测试端口范围"""
        ports = parse_port_range("1-5")
        assert ports == [1, 2, 3, 4, 5]
    
    def test_multiple_ports(self):
        """测试多个端口"""
        ports = parse_port_range("80,443,8080")
        assert 80 in ports
        assert 443 in ports
        assert 8080 in ports
    
    def test_mixed_format(self):
        """测试混合格式"""
        ports = parse_port_range("80,443,1000-1002")
        assert 80 in ports
        assert 443 in ports
        assert 1000 in ports
        assert 1001 in ports
        assert 1002 in ports
    
    def test_common_ports(self):
        """测试常用端口"""
        ports = get_common_ports()
        assert 80 in ports
        assert 443 in ports
        assert 22 in ports


class TestURLParser:
    """URL解析测试"""
    
    def test_extract_domain(self):
        """测试域名提取"""
        assert extract_domain("http://example.com/path") == "example.com"
        assert extract_domain("https://sub.example.com:8080/path") == "sub.example.com:8080"
    
    def test_extract_parameters(self):
        """测试参数提取"""
        params = extract_parameters("http://example.com?a=1&b=2")
        assert params['a'] == '1'
        assert params['b'] == '2'
    
    def test_build_url(self):
        """测试URL构建"""
        url = build_url("http://example.com/path", {"a": "1", "b": "2"})
        assert "a=1" in url
        assert "b=2" in url


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
