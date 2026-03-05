"""
PySecScanner GUI 图形界面
基于 Tkinter 实现
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import asyncio
import threading
import queue
import json
import os
from datetime import datetime
from typing import List, Dict, Optional

# 导入项目模块
from core.logger import logger as global_logger
from core.base import ScanResult, Severity


class AsyncTkinter:
    """在Tkinter中运行异步代码的辅助类"""
    
    def __init__(self, root):
        self.root = root
        self.queue = queue.Queue()
        self.running = True
        
    def run_async(self, coro, callback=None):
        """在后台线程中运行协程"""
        def run():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(coro)
                if callback:
                    self.queue.put(lambda: callback(result))
            except Exception as e:
                self.queue.put(lambda: messagebox.showerror("错误", str(e)))
            finally:
                loop.close()
        
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
    
    def poll(self):
        """检查队列中的回调"""
        try:
            while True:
                callback = self.queue.get_nowait()
                callback()
        except queue.Empty:
            pass
        
        if self.running:
            self.root.after(100, self.poll)


class PySecScannerGUI:
    """PySecScanner 主界面"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("PySecScanner - 安全扫描工具 v2.0")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # 设置样式
        self.setup_styles()
        
        # 异步辅助
        self.async_helper = AsyncTkinter(root)
        self.async_helper.poll()
        
        # 扫描状态
        self.scanning = False
        self.results: List[ScanResult] = []
        
        # 创建界面
        self.create_widgets()
        
        # 加载模块
        self.load_modules()
    
    def setup_styles(self):
        """设置界面样式"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # 自定义样式
        style.configure('Title.TLabel', font=('Microsoft YaHei', 16, 'bold'))
        style.configure('Header.TLabel', font=('Microsoft YaHei', 11, 'bold'))
        style.configure('Status.TLabel', font=('Microsoft YaHei', 10))
        style.configure('Big.TButton', font=('Microsoft YaHei', 11), padding=10)
        style.configure('Critical.TLabel', foreground='#ff4757')
        style.configure('High.TLabel', foreground='#ff6b6b')
        style.configure('Medium.TLabel', foreground='#ffa502')
        style.configure('Low.TLabel', foreground='#2ed573')
        style.configure('Info.TLabel', foreground='#70a1ff')
    
    def create_widgets(self):
        """创建界面组件"""
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # ===== 顶部标题 =====
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        
        title_label = ttk.Label(
            title_frame, 
            text="🔒 PySecScanner - 信息搜集与漏洞扫描工具",
            style='Title.TLabel'
        )
        title_label.pack(side=tk.LEFT)
        
        # ===== 左侧控制面板 =====
        left_frame = ttk.Frame(main_frame, width=300)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_frame.pack_propagate(False)
        
        # 目标输入
        target_frame = ttk.LabelFrame(left_frame, text="扫描目标", padding="10")
        target_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(target_frame, text="目标地址:").pack(anchor=tk.W)
        self.target_entry = ttk.Entry(target_frame, width=35)
        self.target_entry.pack(fill=tk.X, pady=(5, 0))
        ttk.Label(
            target_frame, 
            text="例如: example.com 或 http://192.168.1.1",
            foreground='gray'
        ).pack(anchor=tk.W)
        
        # 模块选择
        modules_frame = ttk.LabelFrame(left_frame, text="扫描模块", padding="10")
        modules_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.module_vars = {}
        modules_list = [
            ("port_scan", "端口扫描", True),
            ("subdomain", "子域名枚举", False),
            ("dir_scan", "目录扫描", False),
            ("fingerprint", "指纹识别", True),
            ("sqli", "SQL注入检测", True),
            ("xss", "XSS检测", True),
            ("ssrf", "SSRF检测", False),
            ("sensitive", "敏感信息检测", True),
            ("poc", "POC验证", False),
        ]
        
        for key, name, default in modules_list:
            var = tk.BooleanVar(value=default)
            self.module_vars[key] = var
            cb = ttk.Checkbutton(modules_frame, text=name, variable=var)
            cb.pack(anchor=tk.W)
        
        # 全选/取消按钮
        btn_frame = ttk.Frame(modules_frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(btn_frame, text="全选", command=self.select_all_modules, width=8).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="取消", command=self.deselect_all_modules, width=8).pack(side=tk.LEFT, padx=5)
        
        # 扫描选项
        options_frame = ttk.LabelFrame(left_frame, text="扫描选项", padding="10")
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(options_frame, text="超时时间(秒):").pack(anchor=tk.W)
        self.timeout_var = tk.StringVar(value="10")
        ttk.Entry(options_frame, textvariable=self.timeout_var, width=10).pack(anchor=tk.W)
        
        ttk.Label(options_frame, text="并发数:").pack(anchor=tk.W, pady=(10, 0))
        self.concurrency_var = tk.StringVar(value="50")
        ttk.Entry(options_frame, textvariable=self.concurrency_var, width=10).pack(anchor=tk.W)
        
        # 操作按钮
        button_frame = ttk.Frame(left_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.scan_button = ttk.Button(
            button_frame, 
            text="🚀 开始扫描", 
            command=self.start_scan,
            style='Big.TButton'
        )
        self.scan_button.pack(fill=tk.X, pady=(0, 5))
        
        self.stop_button = ttk.Button(
            button_frame, 
            text="⏹ 停止扫描", 
            command=self.stop_scan,
            state=tk.DISABLED
        )
        self.stop_button.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Button(
            button_frame, 
            text="📊 导出报告", 
            command=self.export_report
        ).pack(fill=tk.X, pady=(0, 5))
        
        ttk.Button(
            button_frame, 
            text="🗑 清空结果", 
            command=self.clear_results
        ).pack(fill=tk.X)
        
        # ===== 右侧结果面板 =====
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # 进度条
        progress_frame = ttk.Frame(right_frame)
        progress_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.progress_var = tk.StringVar(value="就绪")
        ttk.Label(progress_frame, textvariable=self.progress_var, style='Status.TLabel').pack(side=tk.LEFT)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='indeterminate', length=200)
        self.progress_bar.pack(side=tk.RIGHT)
        
        # 结果标签页
        self.notebook = ttk.Notebook(right_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # 概览标签页
        overview_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(overview_frame, text="📋 概览")
        
        # 统计信息
        stats_frame = ttk.LabelFrame(overview_frame, text="扫描统计", padding="10")
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.stats_labels = {}
        stats_items = [
            ("total", "总发现数"),
            ("critical", "严重"),
            ("high", "高危"),
            ("medium", "中危"),
            ("low", "低危"),
            ("info", "信息")
        ]
        
        for i, (key, name) in enumerate(stats_items):
            row = i // 3
            col = i % 3
            frame = ttk.Frame(stats_frame)
            frame.grid(row=row, column=col, padx=10, pady=5, sticky='w')
            ttk.Label(frame, text=f"{name}:").pack(side=tk.LEFT)
            self.stats_labels[key] = ttk.Label(frame, text="0", font=('Arial', 12, 'bold'))
            self.stats_labels[key].pack(side=tk.LEFT, padx=5)
        
        # 结果列表
        results_frame = ttk.LabelFrame(overview_frame, text="发现结果", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # 结果树形列表
        columns = ('severity', 'type', 'title', 'target')
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=15)
        
        self.results_tree.heading('severity', text='严重程度')
        self.results_tree.heading('type', text='类型')
        self.results_tree.heading('title', text='标题')
        self.results_tree.heading('target', text='目标')
        
        self.results_tree.column('severity', width=80)
        self.results_tree.column('type', width=80)
        self.results_tree.column('title', width=300)
        self.results_tree.column('target', width=200)
        
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.results_tree.bind('<<TreeviewSelect>>', self.on_result_select)
        
        # 详情标签页
        detail_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(detail_frame, text="📝 详情")
        
        self.detail_text = scrolledtext.ScrolledText(detail_frame, wrap=tk.WORD, font=('Consolas', 10))
        self.detail_text.pack(fill=tk.BOTH, expand=True)
        
        # 日志标签页
        log_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(log_frame, text="📜 日志")
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, font=('Consolas', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # ===== 底部状态栏 =====
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.status_var = tk.StringVar(value="就绪 - 请输入目标地址并选择扫描模块")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT)
    
    def load_modules(self):
        """加载模块信息"""
        try:
            from core.scanner import Scanner
            scanner = Scanner()
            modules = scanner.get_available_modules()
            self.log(f"已加载 {len(modules)} 个扫描模块")
        except Exception as e:
            self.log(f"加载模块失败: {e}")
    
    def select_all_modules(self):
        """全选所有模块"""
        for var in self.module_vars.values():
            var.set(True)
    
    def deselect_all_modules(self):
        """取消选择所有模块"""
        for var in self.module_vars.values():
            var.set(False)
    
    def log(self, message: str):
        """添加日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
    
    def update_progress(self, message: str):
        """更新进度"""
        self.progress_var.set(message)
        self.root.update()
    
    def start_scan(self):
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
        
        # 更新状态
        self.scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress_bar.start()
        
        self.log(f"开始扫描目标: {target}")
        self.log(f"选中模块: {', '.join(selected_modules)}")
        
        self.status_var.set(f"正在扫描 {target}...")
        
        # 清空之前的结果
        self.results.clear()
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # 运行扫描
        self.run_scan(target, selected_modules)
    
    def run_scan(self, target: str, modules: List[str]):
        """运行扫描"""
        async def do_scan():
            try:
                from core.scanner import Scanner
                scanner = Scanner()
                
                # 更新配置
                try:
                    timeout = int(self.timeout_var.get())
                    concurrency = int(self.concurrency_var.get())
                    scanner.config.scan.timeout = timeout
                    scanner.config.scan.concurrency = concurrency
                except:
                    pass
                
                # 执行扫描
                report = await scanner.scan(target, modules)
                
                return report
                
            except Exception as e:
                raise e
        
        def on_complete(report):
            self.scanning = False
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.progress_bar.stop()
            
            if report:
                self.results = report.results
                self.display_results()
                self.status_var.set(f"扫描完成 - 发现 {len(self.results)} 个结果")
                self.log(f"扫描完成，共发现 {len(self.results)} 个结果")
            else:
                self.status_var.set("扫描完成 - 未发现结果")
                self.log("扫描完成，未发现结果")
        
        self.async_helper.run_async(do_scan(), on_complete)
    
    def stop_scan(self):
        """停止扫描"""
        self.scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_bar.stop()
        self.status_var.set("扫描已停止")
        self.log("用户停止扫描")
    
    def display_results(self):
        """显示扫描结果"""
        # 更新统计
        stats = {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for result in self.results:
            stats['total'] += 1
            sev = result.severity.value
            if sev in stats:
                stats[sev] += 1
            
            # 添加到树形列表
            self.results_tree.insert('', tk.END, values=(
                sev.upper(),
                result.result_type.value,
                result.title[:50],
                result.target[:30]
            ), tags=(sev,))
        
        # 设置标签颜色
        self.results_tree.tag_configure('critical', foreground='#ff4757')
        self.results_tree.tag_configure('high', foreground='#ff6b6b')
        self.results_tree.tag_configure('medium', foreground='#ffa502')
        self.results_tree.tag_configure('low', foreground='#2ed573')
        self.results_tree.tag_configure('info', foreground='#70a1ff')
        
        # 更新统计标签
        for key, value in stats.items():
            self.stats_labels[key].config(text=str(value))
    
    def on_result_select(self, event):
        """选择结果项时显示详情"""
        selection = self.results_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        index = self.results_tree.index(item)
        
        if index < len(self.results):
            result = self.results[index]
            
            detail = f"""{'='*60}
标题: {result.title}
{'='*60}

类型: {result.result_type.value}
严重程度: {result.severity.value.upper()}
目标: {result.target}

描述:
{result.description}

证据:
{result.evidence}

原始数据:
{json.dumps(result.raw_data, indent=2, ensure_ascii=False) if result.raw_data else 'N/A'}
"""
            self.detail_text.delete('1.0', tk.END)
            self.detail_text.insert('1.0', detail)
            
            # 切换到详情标签页
            self.notebook.select(1)
    
    def export_report(self):
        """导出报告"""
        if not self.results:
            messagebox.showwarning("警告", "没有可导出的结果！")
            return
        
        # 选择保存路径
        filepath = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML文件", "*.html"), ("JSON文件", "*.json"), ("所有文件", "*.*")],
            title="保存报告"
        )
        
        if not filepath:
            return
        
        try:
            if filepath.endswith('.json'):
                # 导出JSON
                data = [r.to_dict() for r in self.results]
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            else:
                # 导出HTML
                self.export_html_report(filepath)
            
            messagebox.showinfo("成功", f"报告已保存到:\n{filepath}")
            self.log(f"报告已导出: {filepath}")
            
        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {e}")
    
    def export_html_report(self, filepath: str):
        """导出HTML报告"""
        html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PySecScanner 扫描报告</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; }
        h1 { color: #333; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }
        .result { border-left: 4px solid #00d4ff; padding: 15px; margin: 10px 0; background: #f9f9f9; }
        .result.critical { border-left-color: #ff4757; }
        .result.high { border-left-color: #ff6b6b; }
        .result.medium { border-left-color: #ffa502; }
        .result.low { border-left-color: #2ed573; }
        .result h3 { margin: 0 0 10px 0; }
        .severity { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 12px; }
        .severity.critical { background: #ff4757; color: white; }
        .severity.high { background: #ff6b6b; color: white; }
        .severity.medium { background: #ffa502; color: white; }
        .severity.low { background: #2ed573; color: white; }
        .severity.info { background: #70a1ff; color: white; }
        .evidence { background: #eee; padding: 10px; margin-top: 10px; font-family: monospace; white-space: pre-wrap; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 PySecScanner 扫描报告</h1>
        <p>生成时间: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
        <p>总发现数: """ + str(len(self.results)) + """</p>
"""
        
        for result in self.results:
            html += f"""
        <div class="result {result.severity.value}">
            <h3>{result.title}</h3>
            <span class="severity {result.severity.value}">{result.severity.value.upper()}</span>
            <span>{result.result_type.value}</span>
            <p><strong>目标:</strong> {result.target}</p>
            <p>{result.description}</p>
            <div class="evidence">{result.evidence}</div>
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def clear_results(self):
        """清空结果"""
        self.results.clear()
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.detail_text.delete('1.0', tk.END)
        self.log_text.delete('1.0', tk.END)
        
        for key in self.stats_labels:
            self.stats_labels[key].config(text="0")
        
        self.status_var.set("结果已清空")
        self.log("结果已清空")


def main():
    """主函数"""
    root = tk.Tk()
    
    # 设置窗口图标（如果有的话）
    try:
        root.iconbitmap('icon.ico')
    except:
        pass
    
    app = PySecScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
