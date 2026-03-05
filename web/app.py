"""
FastAPI Web界面
提供REST API和Web界面
"""

import asyncio
import os
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from core.config import Config
from core.scanner import Scanner, ScanReport
from core.database import Database, db
from core.logger import logger


# Pydantic模型
class ScanRequest(BaseModel):
    target: str
    modules: Optional[List[str]] = None
    options: Optional[Dict[str, Any]] = None


class ScanResponse(BaseModel):
    scan_id: int
    target: str
    status: str
    message: str


# 创建FastAPI应用
app = FastAPI(
    title="PySecScanner",
    description="信息搜集与漏洞扫描工具 Web API",
    version="2.0.0"
)

# CORS配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 全局变量
active_scans: Dict[int, bool] = {}


# ==================== API路由 ====================

@app.get("/")
async def root():
    """返回Web界面"""
    return HTMLResponse(content=get_index_html())


@app.get("/api/stats")
async def get_stats():
    """获取统计信息"""
    return db.get_stats()


@app.get("/api/scans")
async def list_scans(limit: int = 50, offset: int = 0):
    """获取扫描列表"""
    scans = db.get_scans(limit, offset)
    return {
        "scans": [
            {
                "id": s.id,
                "target": s.target,
                "start_time": s.start_time.isoformat(),
                "end_time": s.end_time.isoformat() if s.end_time else None,
                "duration": s.duration,
                "status": s.status,
                "total_findings": s.total_findings,
                "severity_distribution": s.severity_distribution
            }
            for s in scans
        ]
    }


@app.post("/api/scans", response_model=ScanResponse)
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """创建新扫描"""
    # 创建数据库记录
    modules = request.modules or []
    scan_id = db.create_scan(request.target, modules)
    
    # 标记为活动扫描
    active_scans[scan_id] = True
    
    # 后台执行扫描
    background_tasks.add_task(run_scan_task, scan_id, request.target, request.modules)
    
    return ScanResponse(
        scan_id=scan_id,
        target=request.target,
        status="started",
        message="扫描已启动"
    )


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: int):
    """获取扫描详情"""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="扫描不存在")
    
    findings = db.get_findings(scan_id)
    
    return {
        "scan": {
            "id": scan.id,
            "target": scan.target,
            "start_time": scan.start_time.isoformat(),
            "end_time": scan.end_time.isoformat() if scan.end_time else None,
            "duration": scan.duration,
            "status": scan.status,
            "modules": scan.modules,
            "total_findings": scan.total_findings,
            "severity_distribution": scan.severity_distribution
        },
        "findings": [
            {
                "id": f.id,
                "result_type": f.result_type,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "target": f.target,
                "evidence": f.evidence
            }
            for f in findings
        ]
    }


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: int):
    """删除扫描记录"""
    # 停止活动扫描
    if scan_id in active_scans:
        active_scans[scan_id] = False
    
    if db.delete_scan(scan_id):
        return {"message": "扫描已删除"}
    raise HTTPException(status_code=404, detail="扫描不存在")


@app.get("/api/findings/search")
async def search_findings(
    query: str = Query(..., min_length=1),
    severity: Optional[str] = None,
    limit: int = 100
):
    """搜索发现结果"""
    findings = db.search_findings(query, severity, limit)
    return {
        "findings": [
            {
                "id": f.id,
                "scan_id": f.scan_id,
                "result_type": f.result_type,
                "title": f.title,
                "severity": f.severity,
                "target": f.target
            }
            for f in findings
        ]
    }


@app.get("/api/modules")
async def list_modules():
    """获取可用模块列表"""
    scanner = Scanner()
    modules = []
    
    for name in scanner.get_available_modules():
        info = scanner.get_module_info(name)
        if info:
            modules.append({
                "name": name,
                "display_name": info['name'],
                "description": info['description'],
                "version": info['version']
            })
    
    return {"modules": modules}


# ==================== 后台任务 ====================

async def run_scan_task(scan_id: int, target: str, modules: List[str] = None):
    """后台扫描任务"""
    try:
        scanner = Scanner()
        
        # 执行扫描
        report = await scanner.scan(target, modules)
        
        # 检查是否被取消
        if not active_scans.get(scan_id, False):
            db.update_scan(scan_id, status="cancelled")
            return
        
        # 保存结果到数据库
        severity_dist = {}
        for result in report.results:
            # 添加发现
            db.add_finding(scan_id, result.to_dict())
            
            # 统计严重程度
            sev = result.severity.value
            severity_dist[sev] = severity_dist.get(sev, 0) + 1
        
        # 更新扫描状态
        db.update_scan(
            scan_id,
            status="completed",
            total_findings=len(report.results),
            severity_distribution=severity_dist
        )
        
    except Exception as e:
        logger.error(f"扫描任务失败: {e}")
        db.update_scan(scan_id, status="failed")
    
    finally:
        # 清理活动扫描标记
        if scan_id in active_scans:
            del active_scans[scan_id]


# ==================== Web界面HTML ====================

def get_index_html() -> str:
    """返回前端HTML页面"""
    return '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PySecScanner - 安全扫描平台</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: "Segoe UI", system-ui, sans-serif;
            background: linear-gradient(135deg, #0f0f1a 0%, #1a1a2e 100%);
            color: #e0e0e0;
            min-height: 100vh;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header {
            text-align: center;
            padding: 30px 0;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            margin-bottom: 30px;
        }
        .header h1 {
            font-size: 2.5em;
            background: linear-gradient(90deg, #00d4ff, #00ff88);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }
        .header p { color: #888; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .stat-card h3 { color: #888; font-size: 0.9em; margin-bottom: 10px; }
        .stat-card .value { font-size: 2.5em; font-weight: bold; color: #00d4ff; }
        .main-content { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        @media (max-width: 900px) { .main-content { grid-template-columns: 1fr; } }
        .card {
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 25px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .card h2 { color: #00d4ff; margin-bottom: 20px; font-size: 1.3em; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; color: #aaa; }
        .form-group input, .form-group select {
            width: 100%;
            padding: 12px 15px;
            border: 1px solid rgba(255,255,255,0.2);
            border-radius: 8px;
            background: rgba(0,0,0,0.3);
            color: #fff;
            font-size: 1em;
        }
        .form-group input:focus { outline: none; border-color: #00d4ff; }
        .btn {
            padding: 12px 30px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1em;
            font-weight: bold;
            transition: all 0.3s;
        }
        .btn-primary {
            background: linear-gradient(90deg, #00d4ff, #00ff88);
            color: #000;
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(0, 212, 255, 0.3);
        }
        .scan-list { max-height: 400px; overflow-y: auto; }
        .scan-item {
            padding: 15px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            cursor: pointer;
            transition: background 0.3s;
        }
        .scan-item:hover { background: rgba(255,255,255,0.05); }
        .scan-item .target { font-weight: bold; color: #fff; }
        .scan-item .meta { font-size: 0.85em; color: #888; margin-top: 5px; }
        .status-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 0.75em;
            font-weight: bold;
        }
        .status-completed { background: rgba(46, 213, 115, 0.2); color: #2ed573; }
        .status-running { background: rgba(0, 212, 255, 0.2); color: #00d4ff; }
        .status-failed { background: rgba(255, 71, 87, 0.2); color: #ff4757; }
        .severity-critical { color: #ff4757; }
        .severity-high { color: #ff6b6b; }
        .severity-medium { color: #ffa502; }
        .severity-low { color: #2ed573; }
        .severity-info { color: #70a1ff; }
        .modal {
            display: none;
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            background: rgba(0,0,0,0.8);
            z-index: 1000;
            overflow-y: auto;
        }
        .modal.active { display: flex; align-items: center; justify-content: center; padding: 20px; }
        .modal-content {
            background: #1a1a2e;
            border-radius: 15px;
            max-width: 900px;
            width: 100%;
            max-height: 90vh;
            overflow-y: auto;
        }
        .modal-header {
            padding: 20px 25px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .modal-header h2 { color: #00d4ff; }
        .modal-close { background: none; border: none; color: #888; font-size: 1.5em; cursor: pointer; }
        .modal-body { padding: 25px; }
        .finding-item {
            background: rgba(0,0,0,0.3);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid #00d4ff;
        }
        .finding-item.critical { border-left-color: #ff4757; }
        .finding-item.high { border-left-color: #ff6b6b; }
        .finding-item.medium { border-left-color: #ffa502; }
        .finding-item.low { border-left-color: #2ed573; }
        .finding-item h4 { margin-bottom: 10px; }
        .finding-item .evidence {
            background: rgba(0,0,0,0.3);
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            font-size: 0.85em;
            white-space: pre-wrap;
            margin-top: 10px;
        }
        .checkbox-group { display: flex; flex-wrap: wrap; gap: 10px; }
        .checkbox-group label {
            display: flex;
            align-items: center;
            gap: 5px;
            padding: 8px 15px;
            background: rgba(0,0,0,0.3);
            border-radius: 20px;
            cursor: pointer;
            transition: all 0.3s;
        }
        .checkbox-group label:hover { background: rgba(0, 212, 255, 0.2); }
        .loading { text-align: center; padding: 40px; color: #888; }
        .spinner {
            width: 40px; height: 40px;
            border: 3px solid rgba(255,255,255,0.1);
            border-top-color: #00d4ff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 PySecScanner</h1>
            <p>信息搜集与漏洞扫描平台</p>
        </div>
        <div class="stats-grid" id="stats">
            <div class="stat-card"><h3>总扫描数</h3><div class="value" id="total-scans">-</div></div>
            <div class="stat-card"><h3>总发现数</h3><div class="value" id="total-findings">-</div></div>
            <div class="stat-card"><h3>高危漏洞</h3><div class="value severity-high" id="high-findings">-</div></div>
            <div class="stat-card"><h3>近7天扫描</h3><div class="value" id="recent-scans">-</div></div>
        </div>
        <div class="main-content">
            <div class="card">
                <h2>🚀 新建扫描</h2>
                <form id="scan-form">
                    <div class="form-group">
                        <label>目标地址</label>
                        <input type="text" id="target" placeholder="例如: example.com" required>
                    </div>
                    <div class="form-group">
                        <label>扫描模块</label>
                        <div class="checkbox-group" id="modules-checkbox"></div>
                    </div>
                    <button type="submit" class="btn btn-primary">开始扫描</button>
                </form>
            </div>
            <div class="card">
                <h2>📋 扫描历史</h2>
                <div class="scan-list" id="scan-list">
                    <div class="loading"><div class="spinner"></div><p>加载中...</p></div>
                </div>
            </div>
        </div>
    </div>
    <div class="modal" id="scan-modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 id="modal-title">扫描详情</h2>
                <button class="modal-close" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-body" id="modal-body"></div>
        </div>
    </div>
    <script>
        async function loadStats() {
            const res = await fetch('/api/stats');
            const data = await res.json();
            document.getElementById('total-scans').textContent = data.total_scans;
            document.getElementById('total-findings').textContent = data.total_findings;
            document.getElementById('high-findings').textContent = (data.severity_distribution.critical || 0) + (data.severity_distribution.high || 0);
            document.getElementById('recent-scans').textContent = data.recent_scans_7d;
        }
        async function loadModules() {
            const res = await fetch('/api/modules');
            const data = await res.json();
            const container = document.getElementById('modules-checkbox');
            container.innerHTML = data.modules.map(m => `<input type="checkbox" id="mod-${m.name}" value="${m.name}"><label for="mod-${m.name}" title="${m.description}">${m.display_name}</label>`).join('');
        }
        async function loadScans() {
            const res = await fetch('/api/scans');
            const data = await res.json();
            const container = document.getElementById('scan-list');
            if (data.scans.length === 0) { container.innerHTML = '<p style="text-align:center;color:#888;padding:40px;">暂无扫描记录</p>'; return; }
            container.innerHTML = data.scans.map(s => `<div class="scan-item" onclick="showScan(${s.id})"><div class="target">${s.target}</div><div class="meta"><span class="status-badge status-${s.status}">${s.status}</span> ${s.total_findings} 个发现</div></div>`).join('');
        }
        document.getElementById('scan-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const target = document.getElementById('target').value;
            const modules = Array.from(document.querySelectorAll('#modules-checkbox input:checked')).map(cb => cb.value);
            const res = await fetch('/api/scans', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target, modules }) });
            const data = await res.json();
            alert('扫描已启动！ID: ' + data.scan_id);
            setTimeout(loadScans, 1000);
        });
        async function showScan(scanId) {
            const res = await fetch('/api/scans/' + scanId);
            const data = await res.json();
            document.getElementById('modal-title').textContent = '扫描: ' + data.scan.target;
            let html = '<div style="margin-bottom:20px"><p><strong>状态:</strong> <span class="status-badge status-' + data.scan.status + '">' + data.scan.status + '</span></p><p><strong>发现数量:</strong> ' + data.scan.total_findings + '</p></div><h3 style="margin-bottom:15px;color:#00d4ff">发现结果</h3>';
            if (data.findings.length === 0) { html += '<p style="color:#888">未发现问题</p>'; }
            else { html += data.findings.map(f => '<div class="finding-item ' + f.severity + '"><h4>' + f.title + '</h4><p style="color:#888;margin-bottom:10px">' + f.description + '</p><p><strong>严重程度:</strong> <span class="severity-' + f.severity + '">' + f.severity.toUpperCase() + '</span></p>' + (f.evidence ? '<div class="evidence">' + f.evidence + '</div>' : '') + '</div>').join(''); }
            document.getElementById('modal-body').innerHTML = html;
            document.getElementById('scan-modal').classList.add('active');
        }
        function closeModal() { document.getElementById('scan-modal').classList.remove('active'); }
        loadStats(); loadModules(); loadScans();
        setInterval(loadStats, 30000); setInterval(loadScans, 10000);
    </script>
</body>
</html>
'''


def run_server(host: str = "0.0.0.0", port: int = 8000):
    """启动Web服务器"""
    import uvicorn
    print(f"\n🚀 PySecScanner Web界面启动中...")
    print(f"📍 访问地址: http://{host}:{port}")
    print(f"📖 API文档: http://{host}:{port}/docs\n")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_server()
