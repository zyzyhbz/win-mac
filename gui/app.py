"""
PySecScanner GUI - 独立可视化界面
与核心代码解耦，通过导入使用功能
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import asyncio
import threading
import queue
import json
import os
import sys
from datetime import datetime
from typing import List, Dict, Optional, Any

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class ScanResultAdapter:
    """扫描结果适配器 - 解耦GUI与核心数据结构"""
    
    def __init__(self, data: Dict):
        self.result_type = data.get('result_type', 'info')
        self.title = data.get('title', '')
        self.description = data.get('description', '')
        self.severity = data.get('severity', 'info')
        self.target = data.get('target', '')
        self.evidence = data.get('evidence', '')
        self.raw_data = data.get('raw_data', {})
        self.timestamp = data.get('timestamp', 0)
    
    def to_dict(self) -> Dict:
        return {
            'result_type': self.result_type,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'target': self.target,
            'evidence': self.evidence,
            'raw_data': self.raw_data,
            'timestamp': self.timestamp
        }


class ScannerBridge:
    """扫描器桥接类 - 连接GUI与核心扫描器"""
    
    def __init__(self):
        self.scanner = None
        self._initialized = False
    
    def initialize(self):
        """初始化扫描器"""
        if self._initialized:
            return True
        
        try:
            from core.scanner import Scanner
            self.scanner = Scanner()
            self._initialized = True
            return True
        except Exception as e:
            print(f"初始化扫描器失败: {e}")
            return False
    
    def get_modules(self) -> List[Dict]:
        """获取可用模块列表"""
        if not self._initialized:
            self.initialize()
        
        if self.scanner:
            modules = []
            for name in self.scanner.get_available_modules():
                info = self.scanner.get_module_info(name)
                if info:
                    modules.append({
                        'id': name,
                        'name': info.get('name', name),
                        'description': info.get('description', ''),
                        'version': info.get('version', '1.0.0')
                    })
            return modules
        return []
    
    async def scan(self, target: str, modules: List[str] = None, 
                   timeout: int = 10, concurrency: int = 50) -> Dict:
        """执行扫描"""
        if not self._initialized:
            self.initialize()
        
        if not self.scanner:
            raise Exception("扫描器未初始化")
        
        # 更新配置
        self.scanner.config.scan.timeout = timeout
        self.scanner.config.scan.concurrency = concurrency
        
        # 执行扫描
        report = await self.scanner.scan(target, modules)
        
        # 转换结果为字典格式
        return {
            'target': report.target,
            'start_time': report.start_time,
            'end_time': report.end_time,
            'duration': report.duration,
            'results': [r.to_dict() for r in report.results],
            'module_stats': report.module_stats
        }


# 全局扫描器桥接实例
scanner_bridge = ScannerBridge()


class PySecScannerGUI:
    """PySecScanner 图形界面"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("PySecScanner - 安全扫描工具")
        self.root.geometry("1100x750")
        self.root.minsize(900, 600)
        
        # 状态变量
        self.is_scanning = False
        self.scan_results: List[ScanResultAdapter] = []
        self.message_queue = queue.Queue()
        
        # 创建界面
        self._create_styles()
        self._create_widgets()
        
        # 启动消息处理
        self.root.after(100, self._process_messages)
        
        # 初始化扫描器
        self._init_scanner()
    
    def _create_styles(self):
        """创建界面样式"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # 配置颜色
        self.colors = {
            'bg': '#1a1a2e',
            'fg': '#e0e0e0',
            'accent': '#00d4ff',
            'critical': '#ff4757',
            'high': '#ff6b6b',
            'medium': '#ffa502',
            'low': '#2ed573',
            'info': '#70a1ff',
            'input_bg': '#16213e'
        }
        
        self.root.configure(bg=self.colors['bg'])
        
        style.configure('TFrame', background=self.colors['bg'])
        style.configure('TLabel', background=self.colors['bg'], foreground=self.colors['fg'])
        style.configure('TButton', padding=8)
        style.configure('TCheckbutton', background=self.colors['bg'], foreground=self.colors['fg'])
        style.configure('TLabelframe', background=self.colors['bg'], foreground=self.colors['accent'])
        style.configure('TLabelframe.Label', background=self.colors['bg'], foreground=self.colors['accent'])
    
    def _create_widgets(self):
        """创建界面组件"""
        # 主框架
        main_frame = ttk.Frame(self.root, style='TFrame', padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # ===== 顶部标题 =====
        title_frame = ttk.Frame(main_frame, style='TFrame')
        title_frame.pack(fill=tk.X, pady=(0, 15))
        
        title_label = tk.Label(
            title_frame,
            text="PySecScanner",
            font=("Arial", 22, "bold"),
            bg=self.colors['bg'],
            fg=self.colors['accent']
        )
        title_label.pack(side=tk.LEFT)
        
        subtitle = tk.Label(
            title_frame,
            text="信息搜集与漏洞扫描工具",
            font=("Arial", 11),
            bg=self.colors['bg'],
            fg='#888888'
        )
        subtitle.pack(side=tk.LEFT, padx=(15, 0), pady=(8, 0))
        
        # ===== 左侧控制面板 =====
        left_panel = ttk.Frame(main_frame, style='TFrame', width=280)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 15))
        left_panel.pack_propagate(False)
        
        # 目标输入
        target_frame = ttk.LabelFrame(left_panel, text="扫描目标", padding="10")
        target_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(
            target_frame,
            text="目标地址:",
            bg=self.colors['bg'],
            fg='#aaaaaa'
        ).pack(anchor=tk.W)
        
        self.target_entry = tk.Entry(
            target_frame,
            font=("Arial", 11),
            bg=self.colors['input_bg'],
            fg=self.colors['fg'],
            insertbackground=self.colors['fg'],
            relief=tk.FLAT
        )
        self.target_entry.pack(fill=tk.X, pady=(5, 0), ipady=5)
        self.target_entry.insert(0, "http://testphp.vulnweb.com")
        
        tk.Label(
            target_frame,
            text="示例: example.com 或 http://192.168.1.1",
            bg=self.colors['bg'],
            fg='#666666',
            font=("Arial", 8)
        ).pack(anchor=tk.W, pady=(3, 0))
        
        # 模块选择
        modules_frame = ttk.LabelFrame(left_panel, text="扫描模块", padding="10")
        modules_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.module_vars = {}
        default_modules = [
            ("port_scan", "端口扫描", True),
            ("subdomain", "子域名枚举", False),
            ("dir_scan", "目录扫描", True),
            ("sqli", "SQL注入检测", True),
            ("xss", "XSS检测", True),
            ("ssrf", "SSRF检测", False),
            ("sensitive", "敏感信息检测", True),
            ("fingerprint", "指纹识别", False),
        ]
        
        for mod_id, mod_name, default in default_modules:
            var = tk.BooleanVar(value=default)
            self.module_vars[mod_id] = var
            cb = ttk.Checkbutton(
                modules_frame,
                text=mod_name,
                variable=var,
                style='TCheckbutton'
            )
            cb.pack(anchor=tk.W, pady=1)
        
        # 扫描选项
        options_frame = ttk.LabelFrame(left_panel, text="扫描选项", padding="10")
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 超时
        tk.Label(
            options_frame,
            text="超时时间(秒):",
            bg=self.colors['bg'],
            fg='#aaaaaa'
        ).pack(anchor=tk.W)
        
        self.timeout_var = tk.StringVar(value="10")
        tk.Entry(
            options_frame,
            textvariable=self.timeout_var,
            width=8,
            bg=self.colors['input_bg'],
            fg=self.colors['fg'],
            insertbackground=self.colors['fg'],
            relief=tk.FLAT
        ).pack(anchor=tk.W, pady=(3, 8))
        
        # 并发数
        tk.Label(
            options_frame,
            text="并发数:",
            bg=self.colors['bg'],
            fg='#aaaaaa'
        ).pack(anchor=tk.W)
        
        self.concurrency_var = tk.StringVar(value="50")
        tk.Entry(
            options_frame,
            textvariable=self.concurrency_var,
            width=8,
            bg=self.colors['input_bg'],
            fg=self.colors['fg'],
            insertbackground=self.colors['fg'],
            relief=tk.FLAT
        ).pack(anchor=tk.W, pady=(3, 0))
        
        # 操作按钮
        btn_frame = ttk.Frame(left_panel, style='TFrame')
        btn_frame.pack(fill=tk.X, pady=10)
        
        self.scan_btn = tk.Button(
            btn_frame,
            text="开始扫描",
            font=("Arial", 11, "bold"),
            bg=self.colors['accent'],
            fg='#000000',
            relief=tk.FLAT,
            cursor='hand2',
            command=self._start_scan
        )
        self.scan_btn.pack(fill=tk.X, pady=3, ipady=8)
        
        self.stop_btn = tk.Button(
            btn_frame,
            text="停止扫描",
            font=("Arial", 10),
            bg=self.colors['critical'],
            fg='#ffffff',
            relief=tk.FLAT,
            state=tk.DISABLED,
            command=self._stop_scan
        )
        self.stop_btn.pack(fill=tk.X, pady=3, ipady=5)
        
        self.export_btn = tk.Button(
            btn_frame,
            text="导出报告",
            font=("Arial", 10),
            bg=self.colors['low'],
            fg='#000000',
            relief=tk.FLAT,
            command=self._export_report
        )
        self.export_btn.pack(fill=tk.X, pady=3, ipady=5)
        
        self.clear_btn = tk.Button(
            btn_frame,
            text="清空结果",
            font=("Arial", 10),
            bg='#444444',
            fg='#ffffff',
            relief=tk.FLAT,
            command=self._clear_results
        )
        self.clear_btn.pack(fill=tk.X, pady=3, ipady=5)
        
        # ===== 右侧结果面板 =====
        right_panel = ttk.Frame(main_frame, style='TFrame')
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # 进度条
        progress_frame = ttk.Frame(right_panel, style='TFrame')
        progress_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.status_label = tk.Label(
            progress_frame,
            text="就绪",
            font=("Arial", 10),
            bg=self.colors['bg'],
            fg='#888888'
        )
        self.status_label.pack(side=tk.LEFT)
        
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            length=250,
            mode='determinate'
        )
        self.progress_bar.pack(side=tk.RIGHT)
        
        # 结果标签页
        self.notebook = ttk.Notebook(right_panel)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # 结果列表页
        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="扫描结果")
        
        # 结果表格
        columns = ("severity", "type", "title", "target")
        self.results_tree = ttk.Treeview(
            results_frame,
            columns=columns,
            show="headings",
            height=18
        )
        
        self.results_tree.heading("severity", text="严重程度")
        self.results_tree.heading("type", text="类型")
        self.results_tree.heading("title", text="标题")
        self.results_tree.heading("target", text="目标")
        
        self.results_tree.column("severity", width=90)
        self.results_tree.column("type", width=80)
        self.results_tree.column("title", width=280)
        self.results_tree.column("target", width=200)
        
        # 滚动条
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.results_tree.bind("<<TreeviewSelect>>", self._on_result_select)
        
        # 详情页
        detail_frame = ttk.Frame(self.notebook)
        self.notebook.add(detail_frame, text="详细信息")
        
        self.detail_text = scrolledtext.ScrolledText(
            detail_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg=self.colors['input_bg'],
            fg=self.colors['fg'],
            insertbackground=self.colors['fg']
        )
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 日志页
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="扫描日志")
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg='#0f0f1a',
            fg='#00ff00'
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 统计页
        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="统计信息")
        
        self.stats_text = scrolledtext.ScrolledText(
            stats_frame,
            wrap=tk.WORD,
            font=("Arial", 11),
            bg=self.colors['input_bg'],
            fg=self.colors['fg']
        )
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # ===== 底部状态栏 =====
        status_frame = ttk.Frame(self.root, style='TFrame')
        status_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=15, pady=8)
        
        self.bottom_status = tk.Label(
            status_frame,
            text="状态: 就绪",
            font=("Arial", 9),
            bg=self.colors['bg'],
            fg='#888888'
        )
        self.bottom_status.pack(side=tk.LEFT)
        
        self.result_count = tk.Label(
            status_frame,
            text="发现: 0 个结果",
            font=("Arial", 9),
            bg=self.colors['bg'],
            fg=self.colors['accent']
        )
        self.result_count.pack(side=tk.RIGHT)
    
    def _init_scanner(self):
        """初始化扫描器"""
        try:
            if scanner_bridge.initialize():
                self._log("扫描器初始化成功")
                modules = scanner_bridge.get_modules()
                self._log(f"已加载 {len(modules)} 个扫描模块")
            else:
                self._log("扫描器初始化失败", "ERROR")
        except Exception as e:
            self._log(f"初始化错误: {e}", "ERROR")
    
    def _log(self, message: str, level: str = "INFO"):
        """添加日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.message_queue.put(("log", f"[{timestamp}] [{level}] {message}\n"))
    
    def _update_status(self, text: str):
        """更新状态"""
        self.message_queue.put(("status", text))
    
    def _update_progress(self, value: int, text: str):
        """更新进度"""
        self.message_queue.put(("progress", (value, text)))
    
    def _add_result(self, result_data: Dict):
        """添加结果"""
        self.message_queue.put(("result", result_data))
    
    def _process_messages(self):
        """处理消息队列"""
        try:
            while True:
                msg_type, data = self.message_queue.get_nowait()
                
                if msg_type == "log":
                    self.log_text.insert(tk.END, data)
                    self.log_text.see(tk.END)
                elif msg_type == "status":
                    self.status_label.config(text=data)
                    self.bottom_status.config(text=f"状态: {data}")
                elif msg_type == "progress":
                    value, text = data
                    self.progress_bar['value'] = value
                    self.status_label.config(text=text)
                elif msg_type == "result":
                    self._display_result(data)
                elif msg_type == "count":
                    self.result_count.config(text=f"发现: {data} 个结果")
                elif msg_type == "scan_complete":
                    self._on_scan_complete(data)
                elif msg_type == "scan_error":
                    self._on_scan_error(data)
                    
        except queue.Empty:
            pass
        
        self.root.after(100, self._process_messages)
    
    def _display_result(self, result_data: Dict):
        """显示单个结果"""
        result = ScanResultAdapter(result_data)
        self.scan_results.append(result)
        
        severity = result.severity.upper()
        
        item_id = self.results_tree.insert(
            "",
            tk.END,
            values=(
                severity,
                result.result_type,
                result.title[:50],
                result.target[:35]
            )
        )
        
        # 设置颜色标签
        color_map = {
            'CRITICAL': self.colors['critical'],
            'HIGH': self.colors['high'],
            'MEDIUM': self.colors['medium'],
            'LOW': self.colors['low'],
            'INFO': self.colors['info']
        }
        
        self.results_tree.tag_configure(severity, foreground=color_map.get(severity, self.colors['fg']))
        self.results_tree.item(item_id, tags=(severity,))
        
        self.result_count.config(text=f"发现: {len(self.scan_results)} 个结果")
    
    def _on_result_select(self, event):
        """选择结果时显示详情"""
        selection = self.results_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        index = self.results_tree.index(item)
        
        if index < len(self.scan_results):
            result = self.scan_results[index]
            
            detail = f"""{'='*60}
标题: {result.title}
{'='*60}

类型: {result.result_type}
严重程度: {result.severity.upper()}
目标: {result.target}

描述:
{result.description}

证据:
{result.evidence}

原始数据:
{json.dumps(result.raw_data, indent=2, ensure_ascii=False) if result.raw_data else 'N/A'}

时间: {datetime.fromtimestamp(result.timestamp).strftime('%Y-%m-%d %H:%M:%S') if result.timestamp else 'N/A'}
"""
            self.detail_text.delete(1.0, tk.END)
            self.detail_text.insert(tk.END, detail)
            
            # 切换到详情页
            self.notebook.select(1)
    
    def _start_scan(self):
        """开始扫描"""
        target = self.target_entry.get().strip()
        
        if not target:
            messagebox.showwarning("警告", "请输入扫描目标！")
            return
        
        # 获取选中的模块
        selected_modules = [k for k, v in self.module_vars.items() if v.get()]
        
        if not selected_modules:
            messagebox.showwarning("警告", "请至少选择一个扫描模块！")
            return
        
        # 清空之前的结果
        self._clear_results()
        
        # 更新UI状态
        self.is_scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        self._log(f"开始扫描目标: {target}")
        self._log(f"选中模块: {', '.join(selected_modules)}")
        self._update_status("扫描中...")
        self._update_progress(0, "正在初始化...")
        
        # 获取配置
        try:
            timeout = int(self.timeout_var.get())
            concurrency = int(self.concurrency_var.get())
        except ValueError:
            timeout, concurrency = 10, 50
        
        # 在后台线程执行扫描
        scan_thread = threading.Thread(
            target=self._run_scan_thread,
            args=(target, selected_modules, timeout, concurrency),
            daemon=True
        )
        scan_thread.start()
    
    def _run_scan_thread(self, target: str, modules: List[str], timeout: int, concurrency: int):
        """扫描线程"""
        try:
            # 创建事件循环
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            self._update_progress(10, "正在连接目标...")
            
            # 执行扫描
            async def do_scan():
                return await scanner_bridge.scan(target, modules, timeout, concurrency)
            
            result = loop.run_until_complete(do_scan())
            loop.close()
            
            self._update_progress(50, "正在处理结果...")
            
            # 处理结果
            total = len(result.get('results', []))
            for i, res in enumerate(result.get('results', [])):
                self._add_result(res)
                progress = 50 + int((i + 1) / max(total, 1) * 50)
                self._update_progress(progress, f"处理结果 {i+1}/{total}")
            
            self._update_progress(100, "扫描完成")
            self.message_queue.put(("scan_complete", result))
            
        except Exception as e:
            self.message_queue.put(("scan_error", str(e)))
    
    def _on_scan_complete(self, result: Dict):
        """扫描完成处理"""
        self.is_scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
        self._log(f"扫描完成，发现 {len(self.scan_results)} 个结果")
        self._update_status("扫描完成")
        
        # 更新统计信息
        severity_count = {}
        for res in self.scan_results:
            sev = res.severity
            severity_count[sev] = severity_count.get(sev, 0) + 1
        
        stats = f"""{'='*50}
扫描统计报告
{'='*50}

目标: {result.get('target', 'N/A')}
开始时间: {datetime.fromtimestamp(result.get('start_time', 0)).strftime('%Y-%m-%d %H:%M:%S')}
持续时间: {result.get('duration', 0):.2f} 秒

{'='*50}
结果统计
{'='*50}

总发现数: {len(self.scan_results)}

严重程度分布:
"""
        for sev, count in sorted(severity_count.items()):
            stats += f"  {sev.upper()}: {count} 个\n"
        
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, stats)
        
        # 切换到统计页
        self.notebook.select(3)
        
        # 显示完成提示
        messagebox.showinfo(
            "扫描完成",
            f"扫描已完成！\n\n目标: {result.get('target', 'N/A')}\n发现: {len(self.scan_results)} 个结果\n耗时: {result.get('duration', 0):.2f} 秒"
        )
    
    def _on_scan_error(self, error_msg: str):
        """扫描错误处理"""
        self.is_scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
        self._log(f"扫描错误: {error_msg}", "ERROR")
        self._update_status(f"错误: {error_msg}")
        
        messagebox.showerror("扫描错误", f"扫描过程中发生错误:\n{error_msg}")
    
    def _stop_scan(self):
        """停止扫描"""
        self.is_scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
        self._log("用户停止扫描")
        self._update_status("已停止")
    
    def _export_report(self):
        """导出报告"""
        if not self.scan_results:
            messagebox.showwarning("警告", "没有扫描结果可导出！")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[
                ("HTML报告", "*.html"),
                ("JSON报告", "*.json"),
                ("文本报告", "*.txt")
            ],
            title="导出报告"
        )
        
        if not file_path:
            return
        
        try:
            if file_path.endswith('.json'):
                data = {
                    "target": self.target_entry.get(),
                    "scan_time": datetime.now().isoformat(),
                    "total_results": len(self.scan_results),
                    "results": [r.to_dict() for r in self.scan_results]
                }
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            elif file_path.endswith('.html'):
                html = self._generate_html_report()
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(html)
            else:
                text = self._generate_text_report()
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(text)
            
            messagebox.showinfo("成功", f"报告已导出到:\n{file_path}")
            self._log(f"报告已导出: {file_path}")
            
        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {e}")
    
    def _generate_html_report(self) -> str:
        """生成HTML报告"""
        target = self.target_entry.get()
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PySecScanner 扫描报告</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #1a1a2e; color: #e0e0e0; padding: 20px; }}
        h1 {{ color: #00d4ff; }}
        .result {{ background: #16213e; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #00d4ff; }}
        .critical {{ border-left-color: #ff4757; }}
        .high {{ border-left-color: #ff6b6b; }}
        .medium {{ border-left-color: #ffa502; }}
        .low {{ border-left-color: #2ed573; }}
        .info {{ border-left-color: #70a1ff; }}
        .severity {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-right: 10px; }}
        pre {{ background: #0f0f1a; padding: 10px; border-radius: 4px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>PySecScanner 扫描报告</h1>
    <p><strong>目标:</strong> {target}</p>
    <p><strong>扫描时间:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p><strong>发现数量:</strong> {len(self.scan_results)} 个</p>
    <hr>
    <h2>扫描结果</h2>
"""
        
        for result in self.scan_results:
            html += f"""
    <div class="result {result.severity}">
        <p><span class="severity">{result.severity.upper()}</span><strong>{result.title}</strong></p>
        <p><strong>类型:</strong> {result.result_type} | <strong>目标:</strong> {result.target}</p>
        <p>{result.description}</p>
        <pre>{result.evidence}</pre>
    </div>
"""
        
        html += """
</body>
</html>
"""
        return html
    
    def _generate_text_report(self) -> str:
        """生成文本报告"""
        target = self.target_entry.get()
        
        text = f"""
{'='*60}
PySecScanner 扫描报告
{'='*60}

目标: {target}
扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
发现数量: {len(self.scan_results)} 个

{'='*60}
扫描结果
{'='*60}
"""
        
        for i, result in enumerate(self.scan_results, 1):
            text += f"""
[{i}] {result.title}
    严重程度: {result.severity.upper()}
    类型: {result.result_type}
    目标: {result.target}
    描述: {result.description}
    证据: {result.evidence[:200]}
"""
        
        return text
    
    def _clear_results(self):
        """清空结果"""
        self.scan_results.clear()
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.log_text.delete(1.0, tk.END)
        self.detail_text.delete(1.0, tk.END)
        self.stats_text.delete(1.0, tk.END)
        self.progress_bar['value'] = 0
        self.result_count.config(text="发现: 0 个结果")
        self._update_status("就绪")
    
    def run(self):
        """运行应用"""
        self.root.mainloop()


def main():
    """主入口"""
    app = PySecScannerGUI()
    app.run()


if __name__ == "__main__":
    main()
