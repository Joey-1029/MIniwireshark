# gui.py - 完整可运行版本
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import json
import matplotlib.pyplot as plt
from collections import Counter, defaultdict
from datetime import datetime
from packet_capture import PacketCapture

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
        
        # 分析功能按钮
        self.stats_btn = ttk.Button(control_frame, text="📊 统计", 
                                   command=self.show_statistics,
                                   state=tk.DISABLED)
        self.stats_btn.grid(row=0, column=10, padx=5)
        
        self.chart_btn = ttk.Button(control_frame, text="📈 图表",
                                   command=self.generate_charts,
                                   state=tk.DISABLED)
        self.chart_btn.grid(row=0, column=11, padx=5)
        
        self.anon_btn = ttk.Button(control_frame, text="🔒 匿名化",
                                  command=self.anonymize_data,
                                  state=tk.DISABLED)
        self.anon_btn.grid(row=0, column=12, padx=5)
        
        self.anomaly_btn = ttk.Button(control_frame, text="⚠️ 异常检测",
                                     command=self.detect_anomalies,
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
    
    # ====== 必需的方法：以下是缺失的方法 ======
    
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
    
    def show_statistics(self):
        """显示统计信息"""
        if not hasattr(self, 'capture') or not self.capture or not hasattr(self.capture, 'packets') or not self.capture.packets:
            messagebox.showwarning("警告", "没有数据可分析")
            return
        
        # 创建统计窗口
        stats_window = tk.Toplevel(self.root)
        stats_window.title("数据包统计信息")
        stats_window.geometry("700x600")
        
        # 使用Notebook实现多标签页
        notebook = ttk.Notebook(stats_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 标签页1：基本统计
        basic_frame = ttk.Frame(notebook)
        notebook.add(basic_frame, text="📊 基本统计")
        
        basic_text = scrolledtext.ScrolledText(basic_frame, width=80, height=25, font=("Courier", 10))
        basic_text.pack(padx=10, pady=10)
        
        # 计算基本统计
        packets = self.capture.packets
        total_packets = len(packets)
        total_bytes = sum(p['length'] for p in packets)
        avg_size = total_bytes / total_packets if total_packets > 0 else 0
        
        # 协议统计
        protocol_count = Counter([p.get('protocol', '未知') for p in packets])
        
        # 应用统计
        app_count = Counter([p.get('application', '未知') for p in packets if 'application' in p])
        
        # 构建显示文本
        info = "=" * 60 + "\n"
        info += "数据包统计报告\n"
        info += "=" * 60 + "\n\n"
        
        info += "📦 数据包概览\n"
        info += "  " + "-" * 50 + "\n"
        info += f"  总数据包数: {total_packets}\n"
        info += f"  总字节数: {total_bytes:,} 字节\n"
        info += f"  平均包大小: {avg_size:.1f} 字节\n"
        if packets:
            info += f"  抓包时间: {packets[0]['timestamp']} - {packets[-1]['timestamp']}\n\n"
        
        info += "📋 协议分布\n"
        info += "  " + "-" * 50 + "\n"
        for protocol, count in protocol_count.most_common():
            percentage = (count / total_packets) * 100
            bar = "█" * int(percentage / 2)  # 每个█代表2%
            info += f"  {protocol:10} {count:5}包 ({percentage:5.1f}%) {bar}\n"
        
        info += "\n🌐 应用协议\n"
        info += "  " + "-" * 50 + "\n"
        if app_count:
            for app, count in app_count.most_common():
                if app and app != '未知':
                    info += f"  {app:10} {count:5}包\n"
        else:
            info += "  未识别到应用层协议\n"
        
        info += "\n🔢 包大小分布\n"
        info += "  " + "-" * 50 + "\n"
        size_ranges = {'<64': 0, '64-127': 0, '128-255': 0, '256-511': 0, '512-1023': 0, '>=1024': 0}
        for packet in packets:
            size = packet['length']
            if size < 64:
                size_ranges['<64'] += 1
            elif size < 128:
                size_ranges['64-127'] += 1
            elif size < 256:
                size_ranges['128-255'] += 1
            elif size < 512:
                size_ranges['256-511'] += 1
            elif size < 1024:
                size_ranges['512-1023'] += 1
            else:
                size_ranges['>=1024'] += 1
        
        for range_name, count in size_ranges.items():
            if count > 0:
                percentage = (count / total_packets) * 100
                bar = "█" * int(percentage / 2)
                info += f"  {range_name:10} {count:5}包 ({percentage:5.1f}%) {bar}\n"
        
        basic_text.insert(1.0, info)
        basic_text.config(state=tk.DISABLED)
        
        # 标签页2：IP地址统计
        ip_frame = ttk.Frame(notebook)
        notebook.add(ip_frame, text="📍 IP统计")
        
        ip_text = scrolledtext.ScrolledText(ip_frame, width=80, height=25, font=("Courier", 10))
        ip_text.pack(padx=10, pady=10)
        
        # 统计IP地址
        src_ip_count = Counter([p.get('src_ip') for p in packets if p.get('src_ip') and p.get('src_ip') != 'N/A'])
        dst_ip_count = Counter([p.get('dst_ip') for p in packets if p.get('dst_ip') and p.get('dst_ip') != 'N/A'])
        
        ip_info = "=" * 60 + "\n"
        ip_info += "IP地址统计\n"
        ip_info += "=" * 60 + "\n\n"
        
        ip_info += "🔸 源IP地址 (Top 15)\n"
        ip_info += "  " + "-" * 50 + "\n"
        for ip, count in src_ip_count.most_common(15):
            percentage = (count / total_packets) * 100
            ip_info += f"  {ip:20} {count:5}包 ({percentage:5.1f}%)\n"
        
        ip_info += "\n🔹 目标IP地址 (Top 15)\n"
        ip_info += "  " + "-" * 50 + "\n"
        for ip, count in dst_ip_count.most_common(15):
            percentage = (count / total_packets) * 100
            ip_info += f"  {ip:20} {count:5}包 ({percentage:5.1f}%)\n"
        
        ip_text.insert(1.0, ip_info)
        ip_text.config(state=tk.DISABLED)
        
        # 标签页3：端口统计
        port_frame = ttk.Frame(notebook)
        notebook.add(port_frame, text="🔌 端口统计")
        
        port_text = scrolledtext.ScrolledText(port_frame, width=80, height=25, font=("Courier", 10))
        port_text.pack(padx=10, pady=10)
        
        # 统计端口
        dst_port_count = Counter([p.get('dst_port') for p in packets if p.get('dst_port')])
        src_port_count = Counter([p.get('src_port') for p in packets if p.get('src_port')])
        
        port_info = "=" * 60 + "\n"
        port_info += "端口统计\n"
        port_info += "=" * 60 + "\n\n"
        
        port_info += "🎯 目标端口 (Top 20)\n"
        port_info += "  " + "-" * 50 + "\n"
        for port, count in dst_port_count.most_common(20):
            service = self._get_port_service(port)
            percentage = (count / total_packets) * 100 if total_packets > 0 else 0
            port_info += f"  端口 {port:5} ({service:15}) {count:5}包 ({percentage:5.1f}%)\n"
        
        port_info += "\n📡 源端口 (Top 20)\n"
        port_info += "  " + "-" * 50 + "\n"
        for port, count in src_port_count.most_common(20):
            service = "临时端口"
            if int(port) < 1024:
                service = self._get_port_service(port)
            percentage = (count / total_packets) * 100 if total_packets > 0 else 0
            port_info += f"  端口 {port:5} ({service:15}) {count:5}包 ({percentage:5.1f}%)\n"
        
        port_text.insert(1.0, port_info)
        port_text.config(state=tk.DISABLED)
    
    def _get_port_service(self, port):
        """获取端口对应的服务名称"""
        try:
            port_int = int(port)
        except:
            return "未知"
        
        common_ports = {
            20: "FTP-数据", 21: "FTP-控制", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 67: "DHCP服务", 68: "DHCP客户端",
            69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP",
            143: "IMAP", 161: "SNMP", 162: "SNMP Trap", 179: "BGP",
            443: "HTTPS", 465: "SMTPS", 587: "SMTP提交", 636: "LDAPS",
            993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
            8080: "HTTP代理", 8443: "HTTPS备用", 8888: "HTTP备用"
        }
        return common_ports.get(port_int, "未知")
    
    def generate_charts(self):
        """生成统计图表"""
        if not hasattr(self, 'capture') or not self.capture or not hasattr(self.capture, 'packets') or not self.capture.packets:
            messagebox.showwarning("警告", "没有数据可生成图表")
            return
        
        try:
            # 获取数据
            packets = self.capture.packets
            total_packets = len(packets)
            
            # 创建图表窗口
            plt.figure(figsize=(12, 8))
            plt.suptitle('网络流量统计分析图表', fontsize=16, fontweight='bold')
            
            # 子图1：协议分布饼图
            plt.subplot(2, 2, 1)
            protocols = [p.get('protocol', '未知') for p in packets]
            protocol_count = Counter(protocols)
            
            if protocol_count:
                labels = list(protocol_count.keys())
                sizes = list(protocol_count.values())
                
                # 如果协议太多，合并小比例协议
                if len(labels) > 8:
                    total = sum(sizes)
                    new_labels = []
                    new_sizes = []
                    other_size = 0
                    
                    for i, (label, size) in enumerate(zip(labels, sizes)):
                        if size / total > 0.05:  # 大于5%的单独显示
                            new_labels.append(label)
                            new_sizes.append(size)
                        else:
                            other_size += size
                    
                    if other_size > 0:
                        new_labels.append('其他')
                        new_sizes.append(other_size)
                    
                    labels, sizes = new_labels, new_sizes
                
                colors = plt.cm.Set3(range(len(labels)))
                plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors)
                plt.title('协议分布图', fontsize=12)
                plt.axis('equal')
            
            # 子图2：包大小分布直方图
            plt.subplot(2, 2, 2)
            sizes = [p['length'] for p in packets]
            
            plt.hist(sizes, bins=20, edgecolor='black', alpha=0.7, color='skyblue')
            plt.title('数据包大小分布', fontsize=12)
            plt.xlabel('包大小（字节）')
            plt.ylabel('数量')
            plt.grid(True, alpha=0.3)
            
            # 子图3：Top源IP地址
            plt.subplot(2, 2, 3)
            src_ips = [p.get('src_ip') for p in packets if p.get('src_ip') and p.get('src_ip') != 'N/A']
            
            if src_ips:
                src_ip_count = Counter(src_ips)
                top_src = src_ip_count.most_common(10)
                
                if top_src:
                    ips = [ip[:15] + '...' if len(ip) > 15 else ip for ip, count in top_src]
                    counts = [count for ip, count in top_src]
                    
                    plt.barh(ips, counts, color='lightcoral')
                    plt.title('Top 10 源IP地址', fontsize=12)
                    plt.xlabel('包数量')
            
            # 子图4：Top目标IP地址
            plt.subplot(2, 2, 4)
            dst_ips = [p.get('dst_ip') for p in packets if p.get('dst_ip') and p.get('dst_ip') != 'N/A']
            
            if dst_ips:
                dst_ip_count = Counter(dst_ips)
                top_dst = dst_ip_count.most_common(10)
                
                if top_dst:
                    ips = [ip[:15] + '...' if len(ip) > 15 else ip for ip, count in top_dst]
                    counts = [count for ip, count in top_dst]
                    
                    plt.barh(ips, counts, color='lightgreen')
                    plt.title('Top 10 目标IP地址', fontsize=12)
                    plt.xlabel('包数量')
            
            plt.tight_layout()
            plt.show()
            
        except ImportError:
            messagebox.showerror("错误", "需要安装matplotlib库\n运行: pip install matplotlib")
        except Exception as e:
            messagebox.showerror("错误", f"生成图表失败: {str(e)}")
    
    def anonymize_data(self):
        """匿名化数据包中的敏感信息"""
        if not hasattr(self, 'capture') or not self.capture or not hasattr(self.capture, 'packets') or not self.capture.packets:
            messagebox.showwarning("警告", "没有数据可匿名化")
            return
        
        # 询问用户确认
        confirm = messagebox.askyesno("确认", 
            "匿名化将隐藏所有IP和MAC地址的敏感部分\n此操作不可撤销，是否继续？")
        
        if not confirm:
            return
        
        try:
            # 执行匿名化
            anonymized_packets = []
            
            for packet in self.capture.packets:
                # 创建副本
                new_packet = packet.copy()
                
                # 匿名化IP地址（保留前两段）
                if 'src_ip' in new_packet and new_packet['src_ip'] != 'N/A':
                    ip_parts = new_packet['src_ip'].split('.')
                    if len(ip_parts) == 4:
                        new_packet['src_ip'] = f"{ip_parts[0]}.{ip_parts[1]}.x.x"
                
                if 'dst_ip' in new_packet and new_packet['dst_ip'] != 'N/A':
                    ip_parts = new_packet['dst_ip'].split('.')
                    if len(ip_parts) == 4:
                        new_packet['dst_ip'] = f"{ip_parts[0]}.{ip_parts[1]}.x.x"
                
                # 匿名化MAC地址（保留前两段）
                if 'src_mac' in new_packet and new_packet['src_mac'] != 'N/A':
                    mac_parts = new_packet['src_mac'].split(':')
                    if len(mac_parts) == 6:
                        new_packet['src_mac'] = f"{mac_parts[0]}:{mac_parts[1]}:xx:xx:xx:xx"
                
                if 'dst_mac' in new_packet and new_packet['dst_mac'] != 'N/A':
                    mac_parts = new_packet['dst_mac'].split(':')
                    if len(mac_parts) == 6:
                        new_packet['dst_mac'] = f"{mac_parts[0]}:{mac_parts[1]}:xx:xx:xx:xx"
                
                anonymized_packets.append(new_packet)
            
            # 更新数据
            self.capture.packets = anonymized_packets
            
            # 更新显示
            self.clear_table()
            for packet in anonymized_packets:
                self._add_packet_to_table_gui(packet)
            
            messagebox.showinfo("完成", 
                "数据匿名化完成！\n✅ IP地址已隐藏后两段\n✅ MAC地址已隐藏后四段")
            
        except Exception as e:
            messagebox.showerror("错误", f"匿名化失败: {str(e)}")
    
    def detect_anomalies(self):
        """检测异常流量"""
        if not hasattr(self, 'capture') or not self.capture or not hasattr(self.capture, 'packets') or not self.capture.packets:
            messagebox.showwarning("警告", "没有数据可分析")
            return
        
        packets = self.capture.packets
        
        try:
            # 创建异常检测窗口
            anomaly_window = tk.Toplevel(self.root)
            anomaly_window.title("异常流量检测报告")
            anomaly_window.geometry("800x600")
            
            # 使用Notebook
            notebook = ttk.Notebook(anomaly_window)
            notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # 标签页1：端口扫描检测
            scan_frame = ttk.Frame(notebook)
            notebook.add(scan_frame, text="🔍 端口扫描检测")
            
            scan_text = scrolledtext.ScrolledText(scan_frame, width=90, height=25, font=("Courier", 10))
            scan_text.pack(padx=10, pady=10)
            
            scan_info = "=" * 60 + "\n"
            scan_info += "端口扫描检测报告\n"
            scan_info += "=" * 60 + "\n\n"
            
            # 检测端口扫描
            port_scan_results = self._detect_port_scans(packets)
            
            if port_scan_results:
                scan_info += f"⚠️ 检测到 {len(port_scan_results)} 个疑似端口扫描\n\n"
                for i, result in enumerate(port_scan_results, 1):
                    scan_info += f"{i}. 可疑IP: {result['ip']}\n"
                    scan_info += f"   扫描特征: 访问了 {result['port_count']} 个不同端口\n"
                    scan_info += f"   包总数: {result['packet_count']} 个\n"
                    scan_info += f"   时间窗口: {result['time_window']} 秒内\n"
                    scan_info += f"   端口示例: {', '.join(map(str, result['ports'][:5]))}\n\n"
            else:
                scan_info += "✅ 未检测到明显的端口扫描行为\n\n"
                scan_info += "说明:\n"
                scan_info += "- 端口扫描通常表现为同一源IP在短时间内\n"
                scan_info += "  访问多个不同的目标端口\n"
                scan_info += "- 阈值: 10个不同端口/60秒\n"
            
            scan_text.insert(1.0, scan_info)
            scan_text.config(state=tk.DISABLED)
            
            # 标签页2：DDoS检测
            ddos_frame = ttk.Frame(notebook)
            notebook.add(ddos_frame, text="⚡ DDoS检测")
            
            ddos_text = scrolledtext.ScrolledText(ddos_frame, width=90, height=25, font=("Courier", 10))
            ddos_text.pack(padx=10, pady=10)
            
            ddos_info = "=" * 60 + "\n"
            ddos_info += "DDoS攻击检测报告\n"
            ddos_info += "=" * 60 + "\n\n"
            
            # 检测DDoS攻击
            ddos_results = self._detect_ddos_attacks(packets)
            
            if ddos_results:
                ddos_info += f"⚠️ 检测到 {len(ddos_results)} 个疑似DDoS攻击时段\n\n"
                for i, result in enumerate(ddos_results, 1):
                    ddos_info += f"{i}. 攻击时段: {result['start_time']}\n"
                    ddos_info += f"   数据包数: {result['packet_count']} 个/秒\n"
                    ddos_info += f"   持续时间: {result['duration']} 秒\n"
                    ddos_info += f"   平均大小: {result['avg_size']:.1f} 字节\n"
                    ddos_info += f"   目标IP数: {result['target_count']} 个\n\n"
            else:
                ddos_info += "✅ 未检测到明显的DDoS攻击\n\n"
                ddos_info += "说明:\n"
                ddos_info += "- DDoS攻击表现为短时间内大量数据包\n"
                ddos_info += "  通常来自多个源IP攻击单个目标\n"
                ddos_info += "- 阈值: 500包/秒\n"
            
            ddos_text.insert(1.0, ddos_info)
            ddos_text.config(state=tk.DISABLED)
            
            # 标签页3：异常协议检测
            proto_frame = ttk.Frame(notebook)
            notebook.add(proto_frame, text="📡 异常协议检测")
            
            proto_text = scrolledtext.ScrolledText(proto_frame, width=90, height=25, font=("Courier", 10))
            proto_text.pack(padx=10, pady=10)
            
            proto_info = "=" * 60 + "\n"
            proto_info += "异常协议检测报告\n"
            proto_info += "=" * 60 + "\n\n"
            
            # 检测异常协议
            proto_results = self._detect_abnormal_protocols(packets)
            
            if proto_results:
                proto_info += "⚠️ 检测到异常协议使用\n\n"
                for result in proto_results:
                    proto_info += f"🔸 异常协议: {result['protocol']}\n"
                    proto_info += f"   使用频率: {result['count']} 次\n"
                    proto_info += f"   占比: {result['percentage']:.1f}%\n"
                    proto_info += f"   说明: {result['description']}\n\n"
            else:
                proto_info += "✅ 未检测到异常协议使用\n\n"
                proto_info += "正常网络应主要包含以下协议:\n"
                proto_info += "- TCP: 网页浏览、文件传输等\n"
                proto_info += "- UDP: DNS查询、视频流等\n"
                proto_info += "- ICMP: ping测试等\n"
                proto_info += "- ARP: 地址解析协议\n"
            
            proto_text.insert(1.0, proto_info)
            proto_text.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("错误", f"异常检测失败: {str(e)}")
    
    def _detect_port_scans(self, packets, time_window=60, port_threshold=10):
        """检测端口扫描"""
        from collections import defaultdict
        
        # 按源IP分组
        ip_data = defaultdict(lambda: {'ports': set(), 'packets': [], 'count': 0})
        
        for packet in packets:
            if packet.get('protocol') in ['TCP', 'UDP'] and packet.get('src_ip') and packet.get('src_ip') != 'N/A':
                src_ip = packet['src_ip']
                dst_port = packet.get('dst_port')
                
                if dst_port:
                    ip_data[src_ip]['ports'].add(dst_port)
                ip_data[src_ip]['packets'].append(packet)
                ip_data[src_ip]['count'] += 1
        
        # 分析每个IP
        results = []
        for ip, data in ip_data.items():
            if len(data['ports']) >= port_threshold and len(data['packets']) > 0:
                # 计算时间窗口
                times = [p.get('unix_time', 0) for p in data['packets']]
                if len(times) > 1:
                    time_range = max(times) - min(times)
                else:
                    time_range = 0
                
                if time_range <= time_window or time_range == 0:
                    results.append({
                        'ip': ip,
                        'port_count': len(data['ports']),
                        'packet_count': data['count'],
                        'time_window': f"{time_range:.1f}",
                        'ports': list(data['ports'])[:10]
                    })
        
        # 按端口数量排序
        results.sort(key=lambda x: x['port_count'], reverse=True)
        return results
    
    def _detect_ddos_attacks(self, packets, threshold=500, window_size=1):
        """检测DDoS攻击"""
        if len(packets) < 10:
            return []
        
        # 按时间分组（每秒）
        time_groups = defaultdict(list)
        for packet in packets:
            timestamp = packet.get('timestamp', '')
            if timestamp:
                try:
                    # 提取秒级时间
                    time_key = timestamp[:8]  # HH:MM:SS
                    time_groups[time_key].append(packet)
                except:
                    pass
        
        results = []
        for time_key, group_packets in time_groups.items():
            packet_count = len(group_packets)
            
            if packet_count > threshold:
                # 分析这个时间段的流量
                total_bytes = sum(p['length'] for p in group_packets)
                avg_size = total_bytes / packet_count if packet_count > 0 else 0
                
                # 统计目标IP
                target_ips = set()
                for packet in group_packets:
                    if packet.get('dst_ip') and packet.get('dst_ip') != 'N/A':
                        target_ips.add(packet['dst_ip'])
                
                results.append({
                    'start_time': time_key,
                    'packet_count': packet_count,
                    'avg_size': avg_size,
                    'target_count': len(target_ips),
                    'duration': window_size
                })
        
        # 按包数量排序
        results.sort(key=lambda x: x['packet_count'], reverse=True)
        return results
    
    def _detect_abnormal_protocols(self, packets):
        """检测异常协议"""
        protocol_count = Counter([p.get('protocol', '未知') for p in packets])
        total_packets = len(packets)
        
        abnormal = []
        
        # 定义正常协议
        normal_protocols = ['TCP', 'UDP', 'ICMP', 'ARP', 'HTTP', 'HTTPS', 'DNS']
        
        for protocol, count in protocol_count.items():
            if protocol not in normal_protocols and protocol != '未知':
                percentage = (count / total_packets) * 100
                
                # 如果异常协议占比超过5%
                if percentage > 5:
                    description = "异常协议，可能表示恶意活动"
                    
                    if protocol.startswith('IP-'):
                        proto_num = protocol.split('-')[1]
                        description = f"原始IP协议({proto_num})，较少见"
                    
                    abnormal.append({
                        'protocol': protocol,
                        'count': count,
                        'percentage': percentage,
                        'description': description
                    })
        
        return abnormal

def main():
    """主函数"""
    root = tk.Tk()
    app = PacketAnalyzerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()