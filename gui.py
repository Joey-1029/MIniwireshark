# gui.py - 完整可运行版本（已集成B同学模块）
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import json
import matplotlib.pyplot as plt
from collections import Counter, defaultdict
from datetime import datetime
from packet_capture import PacketCapture

# ===== 添加B同学的模块导入 =====
from analyzer import PacketAnalyzer
from utils import anonymize_packets, detect_port_scan, detect_ddos, generate_privacy_report
# ===== B模块导入结束 =====

class PacketAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("迷你Wireshark - 网络抓包分析工具")
        self.root.geometry("1100x700")
        
        # 创建抓包实例
        self.capture = PacketCapture()
        
        # 注册回调，实时更新GUI
        self.capture.register_callback(self.add_packet_to_table)
        
        # 创建界面
        self.setup_ui()
        
        # 存储数据包详细信息
        self.packet_details = {}
        
        # 图表窗口引用
        self.chart_window = None
        
    def setup_ui(self):
        """创建界面组件"""
        
        # ===== 1. 顶部控制面板 =====
        control_frame = ttk.LabelFrame(self.root, text="抓包控制", padding=10)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # 接口选择
        ttk.Label(control_frame, text="网络接口:").grid(row=0, column=0, padx=5)
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(control_frame, textvariable=self.interface_var, width=30)
        self.interface_combo.grid(row=0, column=1, padx=5)
        
        # 更新接口列表
        self.update_interface_list()
        
        # 包数量
        ttk.Label(control_frame, text="包数量:").grid(row=0, column=2, padx=5)
        self.count_var = tk.StringVar(value="20")
        ttk.Spinbox(control_frame, from_=1, to=1000, textvariable=self.count_var, width=10).grid(row=0, column=3, padx=5)
        
        # 过滤条件
        ttk.Label(control_frame, text="过滤:").grid(row=0, column=4, padx=5)
        self.filter_var = tk.StringVar(value="")
        ttk.Entry(control_frame, textvariable=self.filter_var, width=20).grid(row=0, column=5, padx=5)
        
        # 抓包控制按钮
        self.start_btn = ttk.Button(control_frame, text="▶ 开始抓包", command=self.start_capture_thread)
        self.start_btn.grid(row=0, column=6, padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="■ 停止", command=self.stop_capture, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=7, padx=5)
        
        ttk.Button(control_frame, text="🗑️ 清空列表", command=self.clear_table).grid(row=0, column=8, padx=5)
        ttk.Button(control_frame, text="💾 保存", command=self.save_packets).grid(row=0, column=9, padx=5)
        
        # 分析功能按钮 - 使用B同学的模块
        self.stats_btn = ttk.Button(control_frame, text="📊 统计", 
                                   command=self.show_statistics,  # B模块功能
                                   state=tk.DISABLED)
        self.stats_btn.grid(row=0, column=10, padx=5)
        
        self.chart_btn = ttk.Button(control_frame, text="📈 图表",
                                   command=self.generate_charts,  # B模块功能
                                   state=tk.DISABLED)
        self.chart_btn.grid(row=0, column=11, padx=5)
        
        self.anon_btn = ttk.Button(control_frame, text="🔒 匿名化",
                                  command=self.anonymize_data,  # B模块功能
                                  state=tk.DISABLED)
        self.anon_btn.grid(row=0, column=12, padx=5)
        
        self.anomaly_btn = ttk.Button(control_frame, text="⚠️ 异常检测",
                                     command=self.detect_anomalies,  # B模块功能
                                     state=tk.DISABLED)
        self.anomaly_btn.grid(row=0, column=13, padx=5)
        
        # ===== 2. 数据包列表（表格） =====
        list_frame = ttk.LabelFrame(self.root, text="捕获的数据包", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 创建Treeview表格
        columns = ('序号', '时间', '源IP', '源端口', '目标IP', '目标端口', '协议', '长度', '应用')
        self.packet_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        # 设置列宽和标题
        col_widths = [50, 100, 120, 70, 120, 70, 70, 70, 80]
        for i, col in enumerate(columns):
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=col_widths[i])
        
        # 滚动条
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=scrollbar.set)
        
        # 布局
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 绑定点击事件
        self.packet_tree.bind('<<TreeviewSelect>>', self.on_packet_select)
        
        # ===== 3. 数据包详情区域 =====
        detail_frame = ttk.LabelFrame(self.root, text="数据包详情", padding=10)
        detail_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.detail_text = scrolledtext.ScrolledText(detail_frame, height=10, font=("Consolas", 10))
        self.detail_text.pack(fill=tk.BOTH, expand=True)
        
        # ===== 4. 状态栏 =====
        self.status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def update_interface_list(self):
        """更新网络接口列表"""
        interfaces = self.capture.get_available_interfaces()
        self.interface_combo['values'] = interfaces
        if interfaces:
            self.interface_var.set(interfaces[0])
    
    def start_capture_thread(self):
        """在新线程中开始抓包，避免GUI卡死"""
        # 禁用开始按钮，启用停止按钮
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        # 清空表格
        self.clear_table()
        
        # 禁用分析按钮（等待新数据）
        self.stats_btn.config(state=tk.DISABLED)
        self.chart_btn.config(state=tk.DISABLED)
        self.anon_btn.config(state=tk.DISABLED)
        self.anomaly_btn.config(state=tk.DISABLED)
        
        # 更新状态
        self.status_var.set("正在抓包...")
        
        # 在新线程中抓包
        thread = threading.Thread(target=self.start_capture)
        thread.daemon = True
        thread.start()
    
    def start_capture(self):
        """实际的抓包函数"""
        # 获取参数
        interface = self.interface_var.get() if self.interface_var.get() else None
        count = int(self.count_var.get())
        filter_str = self.filter_var.get()
        
        # 设置接口
        if interface:
            self.capture = PacketCapture(interface=interface)
            self.capture.register_callback(self.add_packet_to_table)
        else:
            self.capture = PacketCapture()
            self.capture.register_callback(self.add_packet_to_table)
        
        # 开始抓包
        success = self.capture.start_capture(count=count, filter_str=filter_str)
        
        # 抓包完成后更新状态
        self.root.after(0, self.capture_finished, success)
    
    def add_packet_to_table(self, packet_info):
        """将数据包添加到表格中（由回调函数调用）"""
        # 必须在主线程中更新GUI
        self.root.after(0, self._add_packet_to_table_gui, packet_info)
    
    def _add_packet_to_table_gui(self, packet_info):
        """在GUI线程中添加数据包到表格"""
        # 准备显示的数据
        values = (
            packet_info['no'],
            packet_info['timestamp'],
            packet_info.get('src_ip', 'N/A'),
            packet_info.get('src_port', ''),
            packet_info.get('dst_ip', 'N/A'),
            packet_info.get('dst_port', ''),
            packet_info.get('protocol', '未知'),
            packet_info['length'],
            packet_info.get('application', '')
        )
        
        # 插入表格
        item_id = self.packet_tree.insert('', tk.END, values=values)
        
        # 保存详细信息
        self.packet_details[item_id] = packet_info
        
        # 更新状态
        self.status_var.set(f"已捕获 {len(self.packet_details)} 个数据包")
        
        # 当有数据时启用分析按钮
        if len(self.packet_details) > 0:
            self.stats_btn.config(state=tk.NORMAL)
            self.chart_btn.config(state=tk.NORMAL)
            self.anon_btn.config(state=tk.NORMAL)
            self.anomaly_btn.config(state=tk.NORMAL)
    
    def on_packet_select(self, event):
        """当选择数据包时显示详细信息"""
        selection = self.packet_tree.selection()
        if not selection:
            return
            
        item_id = selection[0]
        if item_id in self.packet_details:
            packet_info = self.packet_details[item_id]
            
            # 清空并显示详细信息
            self.detail_text.delete(1.0, tk.END)
            
            # 构建详细显示
            details = "=" * 60 + "\n"
            details += f"数据包 #{packet_info['no']} 详细信息\n"
            details += "=" * 60 + "\n\n"
            
            # 基本信息
            details += "[基本信息]\n"
            details += f"  时间戳: {packet_info['timestamp']}\n"
            details += f"  长度: {packet_info['length']} 字节\n"
            details += f"  协议: {packet_info.get('protocol', '未知')}\n"
            
            if 'summary' in packet_info:
                details += f"  摘要: {packet_info['summary']}\n"
            
            details += "\n" + "-" * 40 + "\n"
            
            # 网络层信息
            if 'src_ip' in packet_info and packet_info['src_ip'] != 'N/A':
                details += "[网络层]\n"
                details += f"  源IP: {packet_info.get('src_ip', 'N/A')}\n"
                details += f"  目标IP: {packet_info.get('dst_ip', 'N/A')}\n"
                
                if 'src_mac' in packet_info:
                    details += f"  源MAC: {packet_info.get('src_mac', 'N/A')}\n"
                if 'dst_mac' in packet_info:
                    details += f"  目标MAC: {packet_info.get('dst_mac', 'N/A')}\n"
                if 'ttl' in packet_info:
                    details += f"  TTL: {packet_info.get('ttl', 'N/A')}\n"
                
                details += "\n" + "-" * 40 + "\n"
            
            # 传输层信息
            if 'src_port' in packet_info and packet_info['src_port']:
                details += "[传输层]\n"
                details += f"  源端口: {packet_info.get('src_port', '')}\n"
                details += f"  目标端口: {packet_info.get('dst_port', '')}\n"
                
                if 'tcp_flags' in packet_info:
                    details += f"  TCP标志: {packet_info.get('tcp_flags', '')}\n"
                if 'seq_num' in packet_info:
                    details += f"  序列号: {packet_info.get('seq_num', '')}\n"
                if 'ack_num' in packet_info:
                    details += f"  确认号: {packet_info.get('ack_num', '')}\n"
                
                details += "\n" + "-" * 40 + "\n"
            
            # 应用层信息
            if 'application' in packet_info and packet_info['application']:
                details += "[应用层]\n"
                details += f"  应用协议: {packet_info.get('application', '')}\n"
                
                # HTTP信息
                http_fields = ['http_method', 'http_path', 'http_host', 
                              'http_status', 'http_user_agent']
                for field in http_fields:
                    if field in packet_info and packet_info[field]:
                        field_name = field.replace('http_', '').replace('_', ' ').title()
                        details += f"  {field_name}: {packet_info[field]}\n"
            
            # 显示详细信息
            self.detail_text.insert(1.0, details)
    
    # ====== B同学模块的集成函数 ======
    
    def show_statistics(self):
        """统计按钮回调 - 使用B同学的analyzer模块"""
        if not hasattr(self, 'capture') or not self.capture or not hasattr(self.capture, 'packets'):
            messagebox.showwarning("提示", "请先抓取数据包")
            return
        
        packets = self.capture.packets
        if not packets:
            messagebox.showinfo("提示", "没有可分析的数据包")
            return
        
        try:
            # 使用B同学的analyzer模块
            analyzer = PacketAnalyzer(packets)
            stats = analyzer.get_statistics()
            
            # 创建统计窗口
            self._create_statistics_window(stats)
            
        except Exception as e:
            messagebox.showerror("错误", f"统计分析失败: {str(e)}")
    
    def _create_statistics_window(self, stats):
        """创建统计信息显示窗口"""
        stats_window = tk.Toplevel(self.root)
        stats_window.title("数据包统计信息")
        stats_window.geometry("800x600")
        
        # 使用Notebook（标签页）
        notebook = ttk.Notebook(stats_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 标签页1：基本统计
        basic_frame = ttk.Frame(notebook)
        notebook.add(basic_frame, text="📊 基本统计")
        
        text_area = scrolledtext.ScrolledText(basic_frame, width=90, height=25, font=("Courier", 10))
        text_area.pack(padx=10, pady=10)
        
        # 格式化显示统计信息
        display_text = "=" * 60 + "\n"
        display_text += "数据包统计报告\n"
        display_text += "=" * 60 + "\n\n"
        
        display_text += f"总数据包数: {stats.get('total_packets', 0)}\n"
        display_text += f"总字节数: {stats.get('total_bytes', 0):,} 字节\n"
        display_text += f"平均包大小: {stats.get('avg_packet_size', 0):.1f} 字节\n"
        display_text += f"时间范围: {stats.get('time_range', '未知')}\n"
        display_text += f"唯一源IP数: {stats.get('unique_src_ips', 0)}\n"
        display_text += f"唯一目标IP数: {stats.get('unique_dst_ips', 0)}\n\n"
        
        display_text += "协议分布:\n"
        if 'protocol_distribution' in stats:
            total = stats['total_packets']
            for protocol, count in stats['protocol_distribution'].items():
                percentage = (count / total) * 100 if total > 0 else 0
                bar = "█" * int(percentage / 2)  # 每个█代表2%
                display_text += f"  {protocol:10} {count:5} ({percentage:5.1f}%) {bar}\n"
        
        text_area.insert(1.0, display_text)
        text_area.config(state=tk.DISABLED)
        
        # 标签页2：IP统计
        ip_frame = ttk.Frame(notebook)
        notebook.add(ip_frame, text="📍 IP统计")
        
        ip_text = scrolledtext.ScrolledText(ip_frame, width=90, height=25, font=("Courier", 10))
        ip_text.pack(padx=10, pady=10)
        
        ip_info = "=" * 60 + "\n"
        ip_info += "IP地址统计\n"
        ip_info += "=" * 60 + "\n\n"
        
        if 'top_src_ips' in stats and stats['top_src_ips']:
            ip_info += "Top 10 源IP地址:\n"
            ip_info += "-" * 50 + "\n"
            for ip, count in stats['top_src_ips'].items():
                percentage = (count / stats['total_packets']) * 100
                ip_info += f"  {ip:20} {count:5}包 ({percentage:5.1f}%)\n"
        
        if 'top_dst_ips' in stats and stats['top_dst_ips']:
            ip_info += "\nTop 10 目标IP地址:\n"
            ip_info += "-" * 50 + "\n"
            for ip, count in stats['top_dst_ips'].items():
                percentage = (count / stats['total_packets']) * 100
                ip_info += f"  {ip:20} {count:5}包 ({percentage:5.1f}%)\n"
        
        ip_text.insert(1.0, ip_info)
        ip_text.config(state=tk.DISABLED)
    
    def generate_charts(self):
        """图表按钮回调 - 使用B同学的analyzer模块"""
        if not hasattr(self, 'capture') or not self.capture or not hasattr(self.capture, 'packets'):
            messagebox.showwarning("提示", "请先抓取数据包")
            return
        
        packets = self.capture.packets
        if not packets:
            messagebox.showinfo("提示", "没有可分析的数据包")
            return
        
        try:
            # 使用B同学的analyzer模块生成图表
            analyzer = PacketAnalyzer(packets)
            charts = analyzer.generate_all_charts()
            
            if charts:
                messagebox.showinfo("成功", f"已生成 {len(charts)} 个图表文件\n"
                                         "查看当前目录下的PNG文件")
            else:
                messagebox.showinfo("提示", "图表生成完成")
                
        except ImportError:
            messagebox.showerror("错误", "需要安装matplotlib库\n运行: pip install matplotlib")
        except Exception as e:
            messagebox.showerror("错误", f"图表生成失败: {str(e)}")
    
    def anonymize_data(self):
        """匿名化按钮回调 - 使用B同学的utils模块"""
        if not hasattr(self, 'capture') or not self.capture or not hasattr(self.capture, 'packets'):
            messagebox.showwarning("提示", "请先抓取数据包")
            return
        
        packets = self.capture.packets
        if not packets:
            messagebox.showinfo("提示", "没有可分析的数据包")
            return
        
        # 确认操作
        confirm = messagebox.askyesno("确认", 
            "匿名化将隐藏IP和MAC地址的敏感部分\n是否继续？")
        
        if not confirm:
            return
        
        try:
            # 使用B同学的utils模块进行匿名化
            anonymized_packets = anonymize_packets(packets)
            
            # 生成隐私报告
            privacy_report = generate_privacy_report(packets)
            
            # 创建新窗口显示结果
            self._show_anonymization_result(anonymized_packets, privacy_report)
            
        except Exception as e:
            messagebox.showerror("错误", f"匿名化失败: {str(e)}")
    
    def _show_anonymization_result(self, anonymized_packets, privacy_report):
        """显示匿名化结果"""
        result_window = tk.Toplevel(self.root)
        result_window.title("匿名化结果")
        result_window.geometry("700x500")
        
        # 显示隐私报告
        report_text = scrolledtext.ScrolledText(result_window, width=80, height=20, font=("Courier", 10))
        report_text.pack(padx=10, pady=10)
        
        info = "=" * 60 + "\n"
        info += "隐私保护报告\n"
        info += "=" * 60 + "\n\n"
        
        info += f"处理数据包数: {privacy_report.get('total_packets', 0)}\n"
        info += f"唯一IP地址数: {len(privacy_report.get('unique_ips', []))}\n"
        info += f"唯一MAC地址数: {len(privacy_report.get('unique_macs', []))}\n"
        info += f"隐私风险等级: {privacy_report.get('risk_level', '未知')}\n"
        info += f"风险评分: {privacy_report.get('risk_score', 0)}/10\n\n"
        
        info += "处理建议:\n"
        info += f"{privacy_report.get('recommendation', '无')}\n\n"
        
        info += "示例（第一个数据包）:\n"
        if anonymized_packets:
            sample = anonymized_packets[0]
            info += f"  原始IP: 已隐藏\n"
            info += f"  匿名IP: {sample.get('src_ip', 'N/A')} -> {sample.get('dst_ip', 'N/A')}\n"
        
        report_text.insert(1.0, info)
        report_text.config(state=tk.DISABLED)
        
        # 更新按钮
        update_btn = ttk.Button(result_window, text="更新显示匿名化数据",
                              command=lambda: self._update_with_anonymized(anonymized_packets))
        update_btn.pack(pady=10)
    
    def _update_with_anonymized(self, anonymized_packets):
        """用匿名化数据更新界面"""
        # 清空当前显示
        self.clear_table()
        
        # 显示匿名化后的数据
        for packet in anonymized_packets:
            self._add_packet_to_table_gui(packet)
        
        messagebox.showinfo("完成", "界面已更新为匿名化数据")
    
    def detect_anomalies(self):
        """异常检测按钮回调 - 使用B同学的utils模块"""
        if not hasattr(self, 'capture') or not self.capture or not hasattr(self.capture, 'packets'):
            messagebox.showwarning("提示", "请先抓取数据包")
            return
        
        packets = self.capture.packets
        if not packets:
            messagebox.showinfo("提示", "没有可分析的数据包")
            return
        
        try:
            # 使用B同学的utils模块进行异常检测
            port_scans = detect_port_scan(packets, threshold=10)
            ddos_attacks = detect_ddos(packets, packet_threshold=100)
            
            # 显示检测结果
            self._show_anomaly_results(port_scans, ddos_attacks)
            
        except Exception as e:
            messagebox.showerror("错误", f"异常检测失败: {str(e)}")
    
    def _show_anomaly_results(self, port_scans, ddos_attacks):
        """显示异常检测结果"""
        result_window = tk.Toplevel(self.root)
        result_window.title("异常流量检测报告")
        result_window.geometry("900x700")
        
        # 使用Notebook
        notebook = ttk.Notebook(result_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 标签页1：端口扫描检测
        if port_scans:
            scan_frame = ttk.Frame(notebook)
            notebook.add(scan_frame, text=f"🔍 端口扫描 ({len(port_scans)})")
            
            scan_text = scrolledtext.ScrolledText(scan_frame, width=100, height=25, font=("Courier", 10))
            scan_text.pack(padx=10, pady=10)
            
            info = "=" * 60 + "\n"
            info += "端口扫描检测报告\n"
            info += "=" * 60 + "\n\n"
            
            for i, scan in enumerate(port_scans, 1):
                info += f"{i}. 可疑IP: {scan.get('src_ip', '未知')}\n"
                info += f"   扫描端口数: {scan.get('port_count', 0)}\n"
                info += f"   风险等级: {scan.get('risk_level', '未知')}\n"
                if 'description' in scan:
                    info += f"   描述: {scan['description']}\n\n"
                else:
                    info += "\n"
            
            scan_text.insert(1.0, info)
            scan_text.config(state=tk.DISABLED)
        else:
            safe_frame = ttk.Frame(notebook)
            notebook.add(safe_frame, text="✅ 端口扫描")
            
            label = ttk.Label(safe_frame, text="✅ 未检测到端口扫描活动", font=("Arial", 14))
            label.pack(pady=50)
        
        # 标签页2：DDoS检测
        if ddos_attacks:
            ddos_frame = ttk.Frame(notebook)
            notebook.add(ddos_frame, text=f"⚡ DDoS攻击 ({len(ddos_attacks)})")
            
            ddos_text = scrolledtext.ScrolledText(ddos_frame, width=100, height=25, font=("Courier", 10))
            ddos_text.pack(padx=10, pady=10)
            
            info = "=" * 60 + "\n"
            info += "DDoS攻击检测报告\n"
            info += "=" * 60 + "\n\n"
            
            for i, attack in enumerate(ddos_attacks, 1):
                info += f"{i}. 攻击时间: {attack.get('attack_time', '未知')}\n"
                info += f"   攻击类型: {attack.get('attack_type', '未知')}\n"
                info += f"   包速率: {attack.get('packet_rate', '未知')}\n"
                info += f"   风险等级: {attack.get('risk_level', '未知')}\n\n"
            
            ddos_text.insert(1.0, info)
            ddos_text.config(state=tk.DISABLED)
        else:
            safe_frame = ttk.Frame(notebook)
            notebook.add(safe_frame, text="✅ DDoS检测")
            
            label = ttk.Label(safe_frame, text="✅ 未检测到DDoS攻击", font=("Arial", 14))
            label.pack(pady=50)
        
        # 标签页3：安全建议
        advice_frame = ttk.Frame(notebook)
        notebook.add(advice_frame, text="💡 安全建议")
        
        advice_text = scrolledtext.ScrolledText(advice_frame, width=100, height=25, font=("Courier", 10))
        advice_text.pack(padx=10, pady=10)
        
        advice = "=" * 60 + "\n"
        advice += "网络安全建议\n"
        advice += "=" * 60 + "\n\n"
        
        if port_scans or ddos_attacks:
            advice += "⚠️ 检测到安全威胁，建议：\n"
            advice += "1. 检查防火墙规则\n"
            advice += "2. 监控异常IP地址\n"
            advice += "3. 更新安全补丁\n"
            advice += "4. 加强访问控制\n"
        else:
            advice += "✅ 网络状态良好，建议：\n"
            advice += "1. 定期更新系统\n"
            advice += "2. 使用强密码\n"
            advice += "3. 启用日志记录\n"
            advice += "4. 定期安全扫描\n"
        
        advice_text.insert(1.0, advice)
        advice_text.config(state=tk.DISABLED)
    
    # ====== 原有GUI功能 ======
    
    def stop_capture(self):
        """停止抓包"""
        if hasattr(self, 'capture') and self.capture:
            self.capture.stop_capture()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("抓包已停止")
    
    def capture_finished(self, success):
        """抓包完成后的处理"""
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
        if success:
            if hasattr(self.capture, 'packets'):
                packet_count = len(self.capture.packets)
                self.status_var.set(f"抓包完成！共捕获 {packet_count} 个数据包")
                messagebox.showinfo("完成", f"抓包完成！共捕获 {packet_count} 个数据包")
        else:
            self.status_var.set("抓包失败")
            messagebox.showerror("错误", "抓包失败，请检查网络连接和权限")
    
    def clear_table(self):
        """清空表格"""
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        self.packet_details.clear()
        self.detail_text.delete(1.0, tk.END)
        self.status_var.set("列表已清空")
        
        # 禁用分析按钮
        self.stats_btn.config(state=tk.DISABLED)
        self.chart_btn.config(state=tk.DISABLED)
        self.anon_btn.config(state=tk.DISABLED)
        self.anomaly_btn.config(state=tk.DISABLED)
    
    def save_packets(self):
        """保存数据包到文件"""
        if not hasattr(self, 'capture') or not self.capture or not hasattr(self.capture, 'packets') or not self.capture.packets:
            messagebox.showwarning("警告", "没有数据包可保存")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON文件", "*.json"), ("所有文件", "*.*")]
        )
        
        if filename:
            success = self.capture.save_to_file(filename)
            if success:
                messagebox.showinfo("成功", f"数据包已保存到 {filename}")
                self.status_var.set(f"数据已保存到 {filename}")
            else:
                messagebox.showerror("错误", "保存失败")

def main():
    """主函数"""
    root = tk.Tk()
    app = PacketAnalyzerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()