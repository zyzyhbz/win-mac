# PySecScanner Dockerfile
# 信息搜集与漏洞扫描工具

FROM python:3.11-slim

# 设置工作目录
WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY requirements.txt .

# 安装Python依赖
RUN pip install --no-cache-dir -r requirements.txt

# 复制项目文件
COPY . .

# 创建必要的目录
RUN mkdir -p logs outputs data/wordlists data/payloads

# 初始化数据库
RUN python -c "from core.database import db"

# 暴露端口
EXPOSE 8000

# 设置环境变量
ENV PYTHONUNBUFFERED=1

# 默认启动Web服务
CMD ["python", "main.py", "web", "--host", "0.0.0.0", "--port", "8000"]
