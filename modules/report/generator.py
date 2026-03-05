"""
报告生成模块
支持HTML和JSON格式报告
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
from jinja2 import Template

from core.config import Config
from core.logger import Logger
from core.scanner import ScanReport
from core.base import Severity


# HTML报告模板
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PySecScanner 安全扫描报告</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            text-align: center;
            padding: 40px 20px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            margin-bottom: 30px;
            backdrop-filter: blur(10px);
        }
        
        .header h1 {
            font-size: 2.5em;
            color: #00d4ff;
            margin-bottom: 10px;
            text-shadow: 0 0 20px rgba(0, 212, 255, 0.5);
        }
        
        .header .subtitle {
            color: #888;
            font-size: 1.1em;
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 10px;
            padding: 25px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .summary-card h3 {
            color: #888;
            font-size: 0.9em;
            margin-bottom: 10px;
            text-transform: uppercase;
        }
        
        .summary-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #00d4ff;
        }
        
        .severity-critical { color: #ff4757 !important; }
        .severity-high { color: #ff6b6b !important; }
        .severity-medium { color: #ffa502 !important; }
        .severity-low { color: #2ed573 !important; }
        .severity-info { color: #70a1ff !important; }
        
        .section {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .section h2 {
            color: #00d4ff;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid rgba(0, 212, 255, 0.3);
        }
        
        .result-item {
            background: rgba(0, 0, 0, 0.2);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid #00d4ff;
        }
        
        .result-item.critical { border-left-color: #ff4757; }
        .result-item.high { border-left-color: #ff6b6b; }
        .result-item.medium { border-left-color: #ffa502; }
        .result-item.low { border-left-color: #2ed573; }
        .result-item.info { border-left-color: #70a1ff; }
        
        .result-item h4 {
            color: #fff;
            margin-bottom: 10px;
        }
        
        .result-item .meta {
            display: flex;
            gap: 20px;
            margin-bottom: 10px;
            flex-wrap: wrap;
        }
        
        .result-item .meta span {
            color: #888;
            font-size: 0.9em;
        }
        
        .result-item .evidence {
            background: rgba(0, 0, 0, 0.3);
            border-radius: 5px;
            padding: 15px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            white-space: pre-wrap;
            word-break: break-all;
            color: #ccc;
        }
        
        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .severity-badge.critical { background: rgba(255, 71, 87, 0.2); color: #ff4757; }
        .severity-badge.high { background: rgba(255, 107, 107, 0.2); color: #ff6b6b; }
        .severity-badge.medium { background: rgba(255, 165, 2, 0.2); color: #ffa502; }
        .severity-badge.low { background: rgba(46, 213, 115, 0.2); color: #2ed573; }
        .severity-badge.info { background: rgba(112, 161, 255, 0.2); color: #70a1ff; }
        
        .footer {
            text-align: center;
            padding: 30px;
            color: #666;
            font-size: 0.9em;
        }
        
        .no-results {
            text-align: center;
            padding: 40px;
            color: #666;
        }
        
        @media (max-width: 768px) {
            .header h1 {
                font-size: 1.8em;
            }
            
            .summary-card .value {
                font-size: 2em;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 PySecScanner</h1>
            <p class="subtitle">安全扫描报告</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>扫描目标</h3>
                <div class="value" style="font-size: 1.2em;">{{ target }}</div>
            </div>
            <div class="summary-card">
                <h3>扫描耗时</h3>
                <div class="value">{{ "%.2f"|format(duration) }}s</div>
            </div>
            <div class="summary-card">
                <h3>发现问题</h3>
                <div class="value">{{ total_findings }}</div>
            </div>
            <div class="summary-card">
                <h3>扫描时间</h3>
                <div class="value" style="font-size: 1em;">{{ scan_time }}</div>
            </div>
        </div>
        
        <div class="summary">
            {% for sev, count in severity_distribution.items() %}
            <div class="summary-card">
                <h3>{{ sev.upper() }}</h3>
                <div class="value severity-{{ sev }}">{{ count }}</div>
            </div>
            {% endfor %}
        </div>
        
        <div class="section">
            <h2>📋 扫描结果详情</h2>
            {% if results %}
                {% for result in results %}
                <div class="result-item {{ result.severity }}">
                    <h4>{{ result.title }}</h4>
                    <div class="meta">
                        <span class="severity-badge {{ result.severity }}">{{ result.severity.upper() }}</span>
                        <span>📍 {{ result.target }}</span>
                        <span>📁 {{ result.result_type }}</span>
                    </div>
                    <p style="margin-bottom: 10px; color: #aaa;">{{ result.description }}</p>
                    {% if result.evidence %}
                    <div class="evidence">{{ result.evidence }}</div>
                    {% endif %}
                </div>
                {% endfor %}
            {% else %}
                <div class="no-results">
                    <p>✅ 未发现安全问题</p>
                </div>
            {% endif %}
        </div>
        
        <div class="footer">
            <p>Generated by PySecScanner v1.0.0 | {{ generation_time }}</p>
        </div>
    </div>
</body>
</html>
"""


class ReportGenerator:
    """
    报告生成器
    支持HTML和JSON格式
    """
    
    def __init__(self, config: Optional[Config] = None, logger: Optional[Logger] = None):
        self.config = config
        self.logger = logger
    
    def generate(self, report: ScanReport, output_path: str, format: str = 'html') -> str:
        """
        生成报告
        
        Args:
            report: 扫描报告对象
            output_path: 输出路径
            format: 报告格式 (html, json)
            
        Returns:
            生成的报告文件路径
        """
        # 确保输出目录存在
        output_dir = os.path.dirname(output_path)
        if output_dir:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        if format == 'json':
            return self._generate_json(report, output_path)
        else:
            return self._generate_html(report, output_path)
    
    def _generate_html(self, report: ScanReport, output_path: str) -> str:
        """生成HTML报告"""
        template = Template(HTML_TEMPLATE)
        
        # 准备数据
        severity_distribution = {}
        for result in report.results:
            sev = result.severity.value
            severity_distribution[sev] = severity_distribution.get(sev, 0) + 1
        
        # 确保所有严重级别都有
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            if sev not in severity_distribution:
                severity_distribution[sev] = 0
        
        # 按严重程度排序结果
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_results = sorted(
            report.results,
            key=lambda x: severity_order.get(x.severity.value, 5)
        )
        
        html_content = template.render(
            target=report.target,
            duration=report.duration,
            total_findings=len(report.results),
            scan_time=datetime.fromtimestamp(report.start_time).strftime('%Y-%m-%d %H:%M:%S'),
            generation_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            severity_distribution=severity_distribution,
            results=[{
                'title': r.title,
                'description': r.description,
                'severity': r.severity.value,
                'target': r.target,
                'result_type': r.result_type.value,
                'evidence': r.evidence
            } for r in sorted_results]
        )
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        if self.logger:
            self.logger.success(f"HTML报告已生成: {output_path}")
        
        return output_path
    
    def _generate_json(self, report: ScanReport, output_path: str) -> str:
        """生成JSON报告"""
        report_data = {
            'meta': {
                'target': report.target,
                'start_time': report.start_time,
                'end_time': report.end_time,
                'duration': report.duration,
                'total_findings': len(report.results),
                'generated_at': datetime.now().isoformat()
            },
            'summary': report.get_summary(),
            'module_stats': report.module_stats,
            'results': [r.to_dict() for r in report.results]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        if self.logger:
            self.logger.success(f"JSON报告已生成: {output_path}")
        
        return output_path
