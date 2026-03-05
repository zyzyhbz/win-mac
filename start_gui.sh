#!/bin/bash
echo ""
echo "  ========================================"
echo "    PySecScanner - 安全扫描工具 v2.0"
echo "  ======================================="
echo ""
echo "  正在启动图形界面..."
echo ""

# 检查Python
if command -v python3 &> /dev/null; then
    python3 gui/app.py
elif command -v python &> /dev/null; then
    python gui/app.py
else
    echo "  [错误] 未找到 Python！"
    echo ""
    exit 1
fi
