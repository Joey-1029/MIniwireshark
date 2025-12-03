"""
analyzer.py - 数据统计分析模块
B同学负责实现
"""

import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from collections import Counter, defaultdict
from datetime import datetime
import json

class PacketAnalyzer:
    def __init__(self, packets=None):
        """初始化分析器"""
        self.packets = packets or []
        self.stats_cache = {}  # 缓存统计结果
        
    def set_packets(self, packets):
        """设置数据包列表"""
        self.packets = packets
        self.stats_cache.clear()  # 清除缓存
        
    def get_statistics(self):
        """获取全面统计数据"""
        if not self.packets:
            return {"error": "没有可分析的数据包"}
        
        # 如果有缓存，直接返回
        if 'full_stats' in self.stats_cache:
            return self.stats_cache['full_stats']
        
        total_packets = len(self.packets)
        total_bytes = sum(p.get('length', 0) for p in self.packets)
        
        # 协议分布
        protocols = [p.get('protocol', '未知') for p in self.packets]
        protocol_counts = Counter(protocols)
        
        # 应用层协议
        applications = [p.get('application', '未知') for p in self.packets if 'application' in p]
        app_counts = Counter(applications)
        
        # IP地址统计
        src_ips = [p.get('src_ip') for p in self.packets if p.get('src_ip') and p.get('src_ip') != 'N/A']
        dst_ips = [p.get('dst_ip') for p in self.packets if p.get('dst_ip') and p.get('dst_ip') != 'N/A']
        unique_src_ips = len(set(src_ips))
        unique_dst_ips = len(set(dst_ips))
        
        # 端口统计
        src_ports = [p.get('src_port') for p in self.packets if p.get('src_port')]
        dst_ports = [p.get('dst_port') for p in self.packets if p.get('dst_port')]
        
        # 时间范围
        timestamps = [p.get('timestamp') for p in self.packets if p.get('timestamp')]
        time_range = "未知"
        if timestamps:
            time_range = f"{timestamps[0]} - {timestamps[-1]}"
        
        stats = {
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'avg_packet_size': total_bytes / total_packets if total_packets > 0 else 0,
            'unique_src_ips': unique_src_ips,
            'unique_dst_ips': unique_dst_ips,
            'time_range': time_range,
            'protocol_distribution': dict(protocol_counts.most_common()),
            'application_distribution': dict(app_counts.most_common()),
            'top_src_ips': dict(Counter(src_ips).most_common(10)),
            'top_dst_ips': dict(Counter(dst_ips).most_common(10)),
            'top_src_ports': dict(Counter(src_ports).most_common(10)),
            'top_dst_ports': dict(Counter(dst_ports).most_common(10)),
            'traffic_by_second': self._calculate_traffic_by_time(),
        }
        
        # 缓存结果
        self.stats_cache['full_stats'] = stats
        return stats
    
    def _calculate_traffic_by_time(self):
        """按秒计算流量"""
        if not self.packets:
            return {}
        
        # 按秒分组
        traffic_by_sec = defaultdict(lambda: {'count': 0, 'bytes': 0})
        
        for packet in self.packets:
            timestamp = packet.get('timestamp')
            if timestamp:
                # 提取到秒
                time_key = timestamp.split('.')[0] if '.' in timestamp else timestamp
                traffic_by_sec[time_key]['count'] += 1
                traffic_by_sec[time_key]['bytes'] += packet.get('length', 0)
        
        # 转换为标准格式
        return {
            'timestamps': list(traffic_by_sec.keys()),
            'packet_counts': [data['count'] for data in traffic_by_sec.values()],
            'byte_counts': [data['bytes'] for data in traffic_by_sec.values()]
        }
    
    def plot_protocol_distribution(self, save_path="protocol_dist.png"):
        """绘制协议分布图"""
        stats = self.get_statistics()
        
        if 'error' in stats:
            print(stats['error'])
            return
        
        protocols = list(stats['protocol_distribution'].keys())
        counts = list(stats['protocol_distribution'].values())
        
        plt.figure(figsize=(10, 6))
        
        # 饼图
        plt.subplot(1, 2, 1)
        colors = plt.cm.Set3(range(len(protocols)))
        explode = [0.05] * len(protocols)
        plt.pie(counts, labels=protocols, autopct='%1.1f%%', 
                startangle=90, colors=colors, explode=explode)
        plt.title('协议分布饼图')
        
        # 柱状图
        plt.subplot(1, 2, 2)
        plt.bar(range(len(protocols)), counts, color='skyblue', edgecolor='black')
        plt.xticks(range(len(protocols)), protocols, rotation=45, ha='right')
        plt.title('协议分布柱状图')
        plt.xlabel('协议')
        plt.ylabel('包数量')
        plt.tight_layout()
        
        # 添加数值标签
        for i, count in enumerate(counts):
            plt.text(i, count + max(counts)*0.01, str(count), 
                    ha='center', va='bottom', fontsize=9)
        
        plt.tight_layout()
        plt.savefig(save_path, dpi=150)
        plt.show()
        
        print(f"协议分布图已保存: {save_path}")
        return save_path
    
    def plot_traffic_over_time(self, save_path="traffic_over_time.png"):
        """绘制流量时间序列图"""
        if not self.packets:
            print("没有数据可绘制")
            return
        
        # 准备数据
        times = []
        sizes = []
        cumulative = []
        
        for i, packet in enumerate(self.packets):
            if i < 200:  # 限制显示数量，避免过于密集
                times.append(i)
                sizes.append(packet.get('length', 0))
                cumulative.append(sum(sizes))
        
        plt.figure(figsize=(12, 8))
        
        # 子图1：包大小随时间变化
        plt.subplot(2, 2, 1)
        plt.plot(times, sizes, 'b-', alpha=0.7, linewidth=0.5, marker='o', markersize=3)
        plt.title('数据包大小变化')
        plt.xlabel('包序列')
        plt.ylabel('大小（字节）')
        plt.grid(True, alpha=0.3)
        
        # 子图2：累计流量
        plt.subplot(2, 2, 2)
        plt.plot(times, cumulative, 'r-', linewidth=2)
        plt.title('累计流量')
        plt.xlabel('包序列')
        plt.ylabel('累计字节数')
        plt.grid(True, alpha=0.3)
        
        # 子图3：包大小分布直方图
        plt.subplot(2, 2, 3)
        plt.hist(sizes, bins=30, edgecolor='black', alpha=0.7, color='green')
        plt.title('包大小分布')
        plt.xlabel('大小（字节）')
        plt.ylabel('频率')
        plt.grid(True, alpha=0.3)
        
        # 子图4：流量密度图
        plt.subplot(2, 2, 4)
        if times:
            time_diff = np.diff(times) if len(times) > 1 else [0]
            density = np.array(sizes[:-1]) / np.array(time_diff) if len(time_diff) > 0 else [0]
            plt.plot(times[:-1], density, 'g-', alpha=0.7)
            plt.title('流量密度（字节/包间隔）')
            plt.xlabel('包序列')
            plt.ylabel('密度')
            plt.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(save_path, dpi=150)
        plt.show()
        
        print(f"流量时间图已保存: {save_path}")
        return save_path
    
    def plot_ip_analysis(self, save_path="ip_analysis.png"):
        """绘制IP分析图"""
        stats = self.get_statistics()
        
        if 'error' in stats:
            print(stats['error'])
            return
        
        src_ips = list(stats['top_src_ips'].keys())
        src_counts = list(stats['top_src_ips'].values())
        dst_ips = list(stats['top_dst_ips'].keys())
        dst_counts = list(stats['top_dst_ips'].values())
        
        plt.figure(figsize=(14, 6))
        
        # 源IP
        plt.subplot(1, 2, 1)
        if src_ips:
            # 缩短长IP显示
            src_labels = [ip[:15] + '...' if len(ip) > 15 else ip for ip in src_ips]
            plt.barh(src_labels, src_counts, color='lightcoral', edgecolor='black')
            plt.title('Top 10 源IP地址')
            plt.xlabel('包数量')
            # 添加数值
            for i, count in enumerate(src_counts):
                plt.text(count + max(src_counts)*0.01, i, str(count), 
                        va='center', fontsize=9)
        
        # 目标IP
        plt.subplot(1, 2, 2)
        if dst_ips:
            dst_labels = [ip[:15] + '...' if len(ip) > 15 else ip for ip in dst_ips]
            plt.barh(dst_labels, dst_counts, color='lightgreen', edgecolor='black')
            plt.title('Top 10 目标IP地址')
            plt.xlabel('包数量')
            # 添加数值
            for i, count in enumerate(dst_counts):
                plt.text(count + max(dst_counts)*0.01, i, str(count), 
                        va='center', fontsize=9)
        
        plt.tight_layout()
        plt.savefig(save_path, dpi=150)
        plt.show()
        
        print(f"IP分析图已保存: {save_path}")
        return save_path
    
    def generate_all_charts(self):
        """生成所有图表"""
        print("开始生成所有分析图表...")
        
        charts = []
        
        try:
            # 协议分布图
            chart1 = self.plot_protocol_distribution("protocol_dist.png")
            charts.append(chart1)
            
            # 流量时间图
            chart2 = self.plot_traffic_over_time("traffic_over_time.png")
            charts.append(chart2)
            
            # IP分析图
            chart3 = self.plot_ip_analysis("ip_analysis.png")
            charts.append(chart3)
            
            print(f"成功生成 {len(charts)} 个图表文件")
            return charts
            
        except Exception as e:
            print(f"生成图表时出错: {e}")
            return []
    
    def export_statistics(self, filename="statistics_report.json"):
        """导出统计数据到JSON文件"""
        stats = self.get_statistics()
        
        # 添加生成时间
        stats['generated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        stats['analyzer_version'] = '1.0'
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(stats, f, indent=2, ensure_ascii=False)
            print(f"统计数据已导出到: {filename}")
            return True
        except Exception as e:
            print(f"导出失败: {e}")
            return False
    
    def print_summary(self):
        """打印统计摘要"""
        stats = self.get_statistics()
        
        if 'error' in stats:
            print(stats['error'])
            return
        
        print("=" * 60)
        print("网络流量分析报告")
        print("=" * 60)
        print(f"总数据包数: {stats['total_packets']}")
        print(f"总字节数: {stats['total_bytes']:,} 字节")
        print(f"平均包大小: {stats['avg_packet_size']:.1f} 字节")
        print(f"时间范围: {stats['time_range']}")
        print(f"唯一源IP数: {stats['unique_src_ips']}")
        print(f"唯一目标IP数: {stats['unique_dst_ips']}")
        print("\n协议分布:")
        for proto, count in stats['protocol_distribution'].items():
            perc = (count / stats['total_packets']) * 100
            print(f"  {proto:10}: {count:5} ({perc:5.1f}%)")
        print("=" * 60)


# 测试函数
def test_analyzer():
    """测试分析器功能"""
    print("=== PacketAnalyzer 测试 ===")
    
    # 创建测试数据
    test_packets = [
        {
            'no': 1,
            'timestamp': '12:00:01.123',
            'src_ip': '192.168.1.1',
            'dst_ip': '8.8.8.8',
            'protocol': 'TCP',
            'src_port': 12345,
            'dst_port': 80,
            'length': 1500,
            'application': 'HTTP'
        },
        {
            'no': 2,
            'timestamp': '12:00:01.456',
            'src_ip': '192.168.1.2',
            'dst_ip': '8.8.4.4',
            'protocol': 'UDP',
            'src_port': 54321,
            'dst_port': 53,
            'length': 512,
            'application': 'DNS'
        },
        {
            'no': 3,
            'timestamp': '12:00:02.789',
            'src_ip': '192.168.1.1',
            'dst_ip': '8.8.8.8',
            'protocol': 'TCP',
            'src_port': 12345,
            'dst_port': 443,
            'length': 1200,
            'application': 'HTTPS'
        }
    ]
    
    analyzer = PacketAnalyzer(test_packets)
    
    # 测试统计
    print("\n1. 基本统计:")
    stats = analyzer.get_statistics()
    print(f"总包数: {stats['total_packets']}")
    print(f"总字节: {stats['total_bytes']}")
    print(f"协议分布: {stats['protocol_distribution']}")
    
    # 测试图表生成（注释掉以避免弹出窗口影响测试）
    # print("\n2. 生成图表...")
    # analyzer.plot_protocol_distribution("test_protocol.png")
    
    # 测试导出
    print("\n3. 导出数据...")
    analyzer.export_statistics("test_stats.json")
    
    print("\n✅ 测试完成！")


if __name__ == "__main__":
    test_analyzer()
