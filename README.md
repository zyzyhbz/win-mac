# PySecScanner - 信息搜集与漏洞扫描工具 v2.0

一个功能完整的安全扫描框架，用于安全测试和学习。

## ⚠️ 免责声明

**本工具仅供安全研究和授权测试使用。未经授权对他人系统进行扫描是违法行为。使用者需自行承担所有法律责任。**

## ✨ 功能特性

### 信息搜集模块
| 模块 | 功能 |
|-----|------|
| 端口扫描 | TCP连接扫描、服务识别、操作系统探测 |
| 子域名枚举 | 字典爆破、DNS解析 |
| 目录扫描 | 敏感文件发现、状态码分析 |
| Web爬虫 | 自动爬取页面、发现参数、提取表单 |
| 指纹识别 | 识别CMS、框架、服务器、WAF等技术栈 |
| 批量扫描 | 多目标批量扫描、支持文件导入 |

### 漏洞扫描模块
| 模块 | 功能 |
|-----|------|
| SQL注入 | 错误注入、时间盲注、布尔盲注检测 |
| XSS | 反射型XSS检测 |
| SSRF | 服务端请求伪造检测 |
| CSRF | 跨站请求伪造检测 |
| XXE | XML外部实体注入检测 |
| 文件包含 | LFI/RFI检测 |
| 命令注入 | OS命令注入检测 |
| 敏感信息 | API密钥、密码、配置文件泄露检测 |
| POC验证 | 已知漏洞POC验证 |

### 其他特性
- 🌐 **Web界面**: FastAPI + 现代化UI
- 💾 **数据库存储**: SQLite保存扫描历史
- 🔌 **代理支持**: HTTP/SOCKS5代理、代理池
- 📊 **报告生成**: HTML/JSON格式报告
- 🐳 **Docker支持**: 一键部署

## 📦 安装

### 方式一：直接安装

```bash
# 解压项目
tar -xzvf pysec-scanner-v2.tar.gz
cd pysec-scanner

# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或 venv\Scripts\activate  # Windows

# 安装依赖
pip install -r requirements.txt

# 初始化项目
python main.py init
```

### 方式二：Docker部署

```bash
# 构建镜像
docker build -t pysec-scanner .

# 运行容器
docker run -d -p 8000:8000 -v $(pwd)/data:/app/data pysec-scanner

# 或使用docker-compose
docker-compose up -d
```

## 🚀 使用方法

### 命令行模式

```bash
# 查看帮助
python main.py --help

# 完整扫描
python main.py scan http://example.com

# 指定模块扫描
python main.py scan http://example.com -m sqli -m xss -m poc

# 批量扫描
python main.py batch targets.txt

# 端口扫描
python main.py portscan 192.168.1.1 -p common

# 子域名枚举
python main.py subdomain example.com

# 目录扫描
python main.py dirscan http://example.com

# Web爬虫
python main.py crawl http://example.com --depth 3

# 指纹识别
python main.py fingerprint http://example.com

# POC验证
python main.py poc http://example.com

# 单独漏洞扫描
python main.py sqli "http://example.com/page?id=1"
python main.py xss "http://example.com/search?q=test"
python main.py ssrf "http://example.com/fetch?url="
python main.py sensitive http://example.com

# 查看可用模块
python main.py list-modules

# 查看扫描历史
python main.py history

# 查看统计
python main.py stats

# 搜索结果
python main.py search "SQL"
```

### Web界面模式

```bash
# 启动Web服务
python main.py web

# 指定端口
python main.py web -p 9000
```

访问 http://localhost:8000 即可使用Web界面。

### API接口

```bash
# 获取统计
curl http://localhost:8000/api/stats

# 创建扫描
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "http://example.com", "modules": ["sqli", "xss"]}'

# 获取扫描结果
curl http://localhost:8000/api/scans/1

# 获取模块列表
curl http://localhost:8000/api/modules
```

## 📁 项目结构

```
pysec-scanner/
├── main.py                   # 命令行入口
├── config.yaml              # 配置文件
├── requirements.txt         # 依赖列表
├── Dockerfile              # Docker配置
├── docker-compose.yml      # Docker Compose配置
│
├── core/                    # 核心框架
│   ├── config.py           # 配置管理
│   ├── logger.py           # 日志系统
│   ├── base.py             # 模块基类
│   ├── scanner.py          # 扫描器核心
│   └── database.py         # 数据库管理
│
├── modules/                 # 扫描模块
│   ├── recon/              # 信息搜集
│   │   ├── port_scanner.py
│   │   ├── advanced_port_scanner.py
│   │   ├── subdomain_enum.py
│   │   ├── dir_scanner.py
│   │   ├── web_crawler.py
│   │   ├── fingerprint.py
│   │   └── batch_scanner.py
│   │
│   ├── vulnscan/           # 漏洞扫描
│   │   ├── sql_injection.py
│   │   ├── xss_scanner.py
│   │   ├── ssrf_scanner.py
│   │   ├── csrf_scanner.py
│   │   ├── xxe_scanner.py
│   │   ├── file_inclusion.py
│   │   ├── command_injection.py
│   │   ├── sensitive_info.py
│   │   └── poc_scanner.py
│   │
│   └── report/             # 报告生成
│       └── generator.py
│
├── web/                     # Web界面
│   └── app.py              # FastAPI应用
│
├── utils/                   # 工具函数
│   ├── helpers.py
│   └── proxy.py
│
├── tests/                   # 单元测试
│   ├── test_core.py
│   └── test_utils.py
│
└── data/                    # 数据文件
    ├── wordlists/          # 字典文件
    │   ├── subdomains.txt
    │   └── directories.txt
    ├── payloads/           # Payload文件
    │   ├── sqli.txt
    │   └── xss.txt
    └── scanner.db          # SQLite数据库
```

## ⚙️ 配置说明

编辑 `config.yaml` 自定义扫描行为：

```yaml
# 扫描配置
scan:
  timeout: 10          # 请求超时
  concurrency: 50      # 并发数
  proxy: null          # 代理地址

# 端口扫描
port_scan:
  ports: "common"      # common, top100, top1000
  service_detection: true

# 漏洞扫描
vuln_scan:
  sql_injection: true
  xss: true
  ssrf: true
  # ...

# 代理配置
proxy:
  enabled: false
  url: "http://127.0.0.1:8080"
  file: "data/proxies.txt"
  rotate: true
```

## 🔧 扩展开发

### 添加新模块

```python
from core.base import BaseModule, ScanResult, Severity, ResultType

class MyScanner(BaseModule):
    name = "my_scanner"
    description = "我的扫描模块"
    version = "1.0.0"
    
    async def scan(self, target: str) -> list:
        results = []
        
        # 实现扫描逻辑
        # ...
        
        # 添加结果
        results.append(ScanResult(
            result_type=ResultType.VULNERABILITY,
            title="发现漏洞",
            description="漏洞描述",
            severity=Severity.HIGH,
            target=target
        ))
        
        return results
```

### 添加新POC

```python
from modules.vulnscan.poc_scanner import BasePOC, POCResult

class MyPOC(BasePOC):
    name = "My-POC"
    description = "我的POC"
    severity = Severity.HIGH
    
    async def check(self, target: str, session) -> POCResult:
        # 实现POC验证逻辑
        # ...
        return POCResult(
            name=self.name,
            vulnerable=True/False,
            evidence="证据",
            request="请求",
            response="响应"
        )

# 注册POC
POCScanner.register_poc(MyPOC())
```

## 🛡️ 技术栈

- **Python 3.11+**
- **asyncio** - 异步并发
- **aiohttp** - 异步HTTP客户端
- **Click** - 命令行框架
- **Rich** - 终端美化
- **FastAPI** - Web框架
- **SQLite** - 数据存储
- **Jinja2** - 报告模板

## 📚 学习要点

这个项目适合用于学习：

1. **异步编程**: asyncio、aiohttp高并发实现
2. **模块化设计**: 插件式架构，易于扩展
3. **安全测试**: 常见漏洞原理和检测方法
4. **CLI开发**: Click命令行工具开发
5. **Web开发**: FastAPI REST API开发
6. **数据库**: SQLite数据持久化
7. **Docker**: 容器化部署

## 🧪 运行测试

```bash
# 运行所有测试
pytest tests/ -v

# 运行单个测试文件
pytest tests/test_core.py -v
```

## 📄 许可证

MIT License

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📋 更新日志

### v2.0.0
- 新增指纹识别模块
- 新增POC验证模块
- 新增批量扫描功能
- 新增Docker支持
- 新增单元测试
- 新增示例字典和Payload文件
- 优化Web界面
- 优化数据库存储
