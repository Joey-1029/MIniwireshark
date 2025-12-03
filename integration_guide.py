# integration_guide.py
"""
B模块GUI集成指南 - 给A同学
"""

print("=" * 60)
print("B模块GUI集成指南")
print("=" * 60)

guide = """
📌 GUI集成步骤：

1. 在gui.py中添加导入：from analyzer import PacketAnalyzer
from utils import anonymize_packets, detect_port_scan, detect_ddos

2. 为按钮添加回调函数：

🔘 【统计】按钮：
def show_statistics(self):
if hasattr(self, 'capture') and hasattr(self.capture, 'packets'):
packets = self.capture.packets
if packets:
analyzer = PacketAnalyzer(packets)
stats = analyzer.get_statistics()
# 在界面显示stats
self.display_statistics(stats)
else:
messagebox.showinfo("提示", "请先抓取数据包")

🔘 【图表】按钮：
def generate_charts(self):
if hasattr(self, 'capture') and self.capture.packets:
analyzer = PacketAnalyzer(self.capture.packets)
analyzer.generate_all_charts()
messagebox.showinfo("成功", "图表已生成！")


🔘 【匿名化】按钮：
def anonymize_data(self):
if hasattr(self, 'capture') and self.capture.packets:
anonymized = anonymize_packets(self.capture.packets)
# 更新显示匿名化数据
self.update_packet_display(anonymized)
messagebox.showinfo("完成", "数据已匿名化")


🔘 【异常检测】按钮：
def detect_anomalies(self):
if hasattr(self, 'capture') and self.capture.packets:
scans = detect_port_scan(self.capture.packets)
ddos = detect_ddos(self.capture.packets)
# 显示检测结果
self.show_anomaly_results(scans, ddos)


3. 数据格式说明：
B模块接受的数据格式与packet_capture.py输出一致：
[
{
'no': 1,
'timestamp': '时间',
'length': 包大小,
'protocol': '协议类型',
'src_ip': '源IP', # 可选
'dst_ip': '目标IP', # 可选
'src_port': 端口, # 可选
'dst_port': 端口, # 可选
'application': '应用' # 可选
},
...
]


4. 错误处理：
- 空数据：B模块会返回 {'error': '没有可分析的数据包'}
- 格式错误：会抛出异常，建议用try-catch包装

5. 性能提示：
- 大数据集时，图表生成可能较慢
- 匿名化不影响原始数据，返回新列表
- 异常检测算法已优化，处理速度快

💡 快速测试：
运行 test_for_A.py 验证集成准备情况。
"""

print(guide)

# 保存到文件
with open("GUI集成指南.txt", "w", encoding="utf-8") as f:
    f.write(guide)

print("\n✅ 集成指南已保存: GUI集成指南.txt")
print("\n📞 如有集成问题，B同学随时提供支持！")
input("\n按Enter退出...")


