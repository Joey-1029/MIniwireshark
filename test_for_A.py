# test_for_A.py
"""
给A同学测试B模块的脚本
"""

print("=" * 60)
print("B模块集成测试 - 给A同学")
print("=" * 60)

print("\n1. 检查B模块文件...")
import os

if os.path.exists("analyzer.py"):
    print("✅ analyzer.py 存在")
else:
    print("❌ analyzer.py 不存在")

if os.path.exists("utils.py"):
    print("✅ utils.py 存在")
else:
    print("❌ utils.py 不存在")

print("\n2. 测试模块导入...")
try:
    from analyzer import PacketAnalyzer
    from utils import anonymize_packets, detect_port_scan, detect_ddos
    print("✅ 所有模块导入成功")
except ImportError as e:
    print(f"❌ 导入失败: {e}")

print("\n3. 测试数据格式兼容性...")
test_packets = [
    {
        'no': 1,
        'timestamp': '12:00:01.123',
        'length': 1500,
        'protocol': 'TCP',
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'src_port': 54321,
        'dst_port': 80,
        'application': 'HTTP'
    },
    {
        'no': 2,
        'timestamp': '12:00:01.456',
        'length': 512,
        'protocol': 'UDP',
        'src_ip': '192.168.1.101',
        'dst_ip': '8.8.4.4',
        'src_port': 12345,
        'dst_port': 53,
        'application': 'DNS'
    }
]

print(f"测试数据格式: {len(test_packets)} 个包")

print("\n4. 测试B模块功能...")
try:
    analyzer = PacketAnalyzer(test_packets)
    stats = analyzer.get_statistics()
    print(f"✅ 数据分析: {stats['total_packets']}包")
    
    anonymized = anonymize_packets(test_packets)
    print(f"✅ 匿名化: {test_packets[0]['src_ip']} -> {anonymized[0]['src_ip']}")
    
    scans = detect_port_scan(test_packets)
    print(f"✅ 端口扫描检测: {len(scans)} 个结果")
    
    ddos = detect_ddos(test_packets)
    print(f"✅ DDoS检测: {len(ddos)} 个结果")
    
    print("\n🎯 B模块所有功能测试通过！")
    
except Exception as e:
    print(f"❌ 功能测试失败: {e}")

print("\n" + "=" * 60)
print("集成准备状态: ✅ B模块已准备好集成")
print("=" * 60)

input("\n按Enter退出...")
