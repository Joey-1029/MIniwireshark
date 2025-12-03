"""
utils.py - 工具函数和算法模块
B同学负责实现 - 修正版
"""

import hashlib
import ipaddress
from collections import defaultdict, Counter
from datetime import datetime
import json

class PrivacyUtils:
    """隐私保护工具类"""
    
    @staticmethod
    def anonymize_ip(ip_address, method='hash'):
        """
        匿名化IP地址
        
        参数:
            ip_address: 原始IP地址
            method: 匿名化方法 ('hash', 'mask', 'fake')
        
        返回:
            匿名化后的IP
        """
        if not ip_address or ip_address == 'N/A':
            return '0.0.0.0'
        
        try:
            # 检查是否为有效IP
            ip = ipaddress.ip_address(ip_address)
        except ValueError:
            return 'Invalid IP'
        
        if method == 'hash':
            # 方法1: 哈希匿名化
            hash_obj = hashlib.sha256(ip_address.encode())
            hash_hex = hash_obj.hexdigest()[:8]
            if isinstance(ip, ipaddress.IPv4Address):
                return f"anon-{hash_hex}.0.0.0"
            else:
                return f"anon-{hash_hex}::"
        
        elif method == 'mask':
            # 方法2: 掩码匿名化（保留前两段）
            parts = ip_address.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.x.x"
            return ip_address
        
        elif method == 'fake':
            # 方法3: 生成假IP
            if isinstance(ip, ipaddress.IPv4Address):
                hash_int = int(hashlib.sha256(ip_address.encode()).hexdigest()[:8], 16)
                return f"192.168.{hash_int % 256}.{(hash_int // 256) % 256}"
            else:
                return "fd00::1"
        
        else:
            return ip_address
    
    @staticmethod
    def anonymize_mac(mac_address):
        """匿名化MAC地址"""
        if not mac_address or mac_address == 'N/A':
            return '00:00:00:00:00:00'
        
        parts = mac_address.split(':')
        if len(parts) == 6:
            # 保留前两段，其余匿名化
            return f"{parts[0]}:{parts[1]}:xx:xx:xx:xx"
        return mac_address
    
    @staticmethod
    def anonymize_packets(packets, ip_method='mask', anonymize_mac=True):
        """批量匿名化数据包"""
        anonymized = []
        
        for packet in packets:
            # 创建副本
            pkt_copy = packet.copy()
            
            # 匿名化IP
            if 'src_ip' in pkt_copy and pkt_copy['src_ip'] != 'N/A':
                pkt_copy['src_ip'] = PrivacyUtils.anonymize_ip(pkt_copy['src_ip'], ip_method)
            
            if 'dst_ip' in pkt_copy and pkt_copy['dst_ip'] != 'N/A':
                pkt_copy['dst_ip'] = PrivacyUtils.anonymize_ip(pkt_copy['dst_ip'], ip_method)
            
            # 匿名化MAC
            if anonymize_mac:
                if 'src_mac' in pkt_copy and pkt_copy['src_mac'] != 'N/A':
                    pkt_copy['src_mac'] = PrivacyUtils.anonymize_mac(pkt_copy['src_mac'])
                
                if 'dst_mac' in pkt_copy and pkt_copy['dst_mac'] != 'N/A':
                    pkt_copy['dst_mac'] = PrivacyUtils.anonymize_mac(pkt_copy['dst_mac'])
            
            # 匿名化HTTP信息（如果存在）
            http_fields = ['http_host', 'http_user_agent', 'http_referer']
            for field in http_fields:
                if field in pkt_copy and pkt_copy[field]:
                    # 简单哈希处理
                    pkt_copy[field] = f"anon_{hash(pkt_copy[field]) % 10000}"
            
            anonymized.append(pkt_copy)
        
        return anonymized
    
    @staticmethod
    def generate_privacy_report(packets):
        """生成隐私泄露风险报告"""
        report = {
            'total_packets': len(packets),
            'unique_ips': set(),
            'unique_macs': set(),
            'http_info_count': 0,
            'dns_queries': []
        }
        
        for packet in packets:
            # 收集IP
            if packet.get('src_ip') and packet.get('src_ip') != 'N/A':
                report['unique_ips'].add(packet['src_ip'])
            if packet.get('dst_ip') and packet.get('dst_ip') != 'N/A':
                report['unique_ips'].add(packet['dst_ip'])
            
            # 收集MAC
            if packet.get('src_mac') and packet.get('src_mac') != 'N/A':
                report['unique_macs'].add(packet['src_mac'])
            if packet.get('dst_mac') and packet.get('dst_mac') != 'N/A':
                report['unique_macs'].add(packet['dst_mac'])
            
            # HTTP信息
            if any(field in packet for field in ['http_host', 'http_user_agent', 'http_referer']):
                report['http_info_count'] += 1
            
            # DNS查询
            if 'dns_query' in packet and packet['dns_query']:
                report['dns_queries'].append(packet['dns_query'])
        
        report['unique_ips'] = list(report['unique_ips'])
        report['unique_macs'] = list(report['unique_macs'])
        
        # 评估风险等级
        risk_score = 0
        if len(report['unique_ips']) > 10:
            risk_score += 2
        if len(report['unique_macs']) > 5:
            risk_score += 3
        if report['http_info_count'] > 5:
            risk_score += 2
        if report['dns_queries']:
            risk_score += 1
        
        if risk_score >= 5:
            report['risk_level'] = '高危'
        elif risk_score >= 3:
            report['risk_level'] = '中危'
        else:
            report['risk_level'] = '低危'
        
        report['risk_score'] = risk_score
        report['recommendation'] = "建议启用匿名化功能以保护隐私" if risk_score >= 3 else "隐私风险较低"
        
        return report


class AnomalyDetector:
    """异常流量检测类"""
    
    def __init__(self, packets=None):
        self.packets = packets or []
    
    def set_packets(self, packets):
        self.packets = packets
    
    def detect_port_scan(self, threshold=10, time_window=60):
        """检测端口扫描攻击"""
        if not self.packets:
            return []
        
        # 按源IP分组
        ip_scan_data = defaultdict(lambda: {
            'ports': set(),
            'timestamps': [],
            'target_ips': set()
        })
        
        for packet in self.packets:
            if packet.get('protocol') in ['TCP', 'UDP']:
                src_ip = packet.get('src_ip')
                dst_port = packet.get('dst_port')
                dst_ip = packet.get('dst_ip')
                timestamp = packet.get('unix_time', 0)
                
                if src_ip and src_ip != 'N/A' and dst_port:
                    ip_scan_data[src_ip]['ports'].add(dst_port)
                    ip_scan_data[src_ip]['timestamps'].append(timestamp)
                    if dst_ip and dst_ip != 'N/A':
                        ip_scan_data[src_ip]['target_ips'].add(dst_ip)
        
        # 分析每个IP
        results = []
        for src_ip, data in ip_scan_data.items():
            port_count = len(data['ports'])
            target_count = len(data['target_ips'])
            
            # 检查时间窗口
            time_span = 0
            if data['timestamps']:
                time_span = max(data['timestamps']) - min(data['timestamps'])
            
            # 判断是否为端口扫描
            is_scan = False
            scan_type = ""
            
            if port_count >= threshold:
                if target_count == 1 and port_count > 20:
                    # 垂直扫描：同一目标多个端口
                    is_scan = True
                    scan_type = "垂直扫描"
                elif target_count > 3 and time_span < time_window:
                    # 水平扫描：多个目标相同端口
                    is_scan = True
                    scan_type = "水平扫描"
                elif port_count > 50:
                    # 全端口扫描
                    is_scan = True
                    scan_type = "全端口扫描"
            
            if is_scan:
                results.append({
                    'src_ip': src_ip,
                    'scan_type': scan_type,
                    'port_count': port_count,
                    'target_count': target_count,
                    'time_span': f"{time_span:.1f}秒",
                    'risk_level': '高危' if port_count > 100 else '中危',
                    'description': f"{src_ip} 疑似进行{scan_type}，扫描了{port_count}个端口"
                })
        
        # 按端口数量排序
        results.sort(key=lambda x: x['port_count'], reverse=True)
        return results
    
    def detect_ddos(self, packet_threshold=100, time_window=1):
        """检测DDoS攻击"""
        if not self.packets:
            return []
        
        # 按时间窗口分组（秒）
        time_groups = defaultdict(list)
        for packet in self.packets:
            timestamp = packet.get('timestamp', '')
            if timestamp:
                try:
                    # 提取到秒
                    time_key = timestamp.split('.')[0] if '.' in timestamp else timestamp
                    time_groups[time_key].append(packet)
                except:
                    pass
        
        results = []
        for time_key, packets_in_second in time_groups.items():
            packet_count = len(packets_in_second)
            
            if packet_count >= packet_threshold:
                # 分析这一秒的流量特征
                total_bytes = sum(p.get('length', 0) for p in packets_in_second)
                avg_size = total_bytes / packet_count if packet_count > 0 else 0
                
                # 统计源IP多样性
                src_ips = [p.get('src_ip') for p in packets_in_second 
                          if p.get('src_ip') and p.get('src_ip') != 'N/A']
                unique_src_ips = len(set(src_ips))
                
                # 统计目标IP集中度
                dst_ips = [p.get('dst_ip') for p in packets_in_second 
                          if p.get('dst_ip') and p.get('dst_ip') != 'N/A']
                dst_ip_counter = Counter(dst_ips)
                top_dst_ip = dst_ip_counter.most_common(1)[0] if dst_ip_counter else None
                
                # 计算协议分布
                protocols = [p.get('protocol', '未知') for p in packets_in_second]
                protocol_counter = Counter(protocols)
                
                # 判断是否为DDoS
                is_ddos = False
                attack_type = ""
                
                if packet_count > 1000:
                    is_ddos = True
                    attack_type = "大流量DDoS"
                elif unique_src_ips > 50 and top_dst_ip and top_dst_ip[1] > packet_count * 0.7:
                    is_ddos = True
                    attack_type = "分布式DDoS"
                elif 'ICMP' in protocol_counter and protocol_counter['ICMP'] > packet_count * 0.8:
                    is_ddos = True
                    attack_type = "ICMP洪水攻击"
                elif packet_count > 500 and avg_size < 100:
                    is_ddos = True
                    attack_type = "小包洪水攻击"
                
                if is_ddos:
                    results.append({
                        'attack_time': time_key,
                        'attack_type': attack_type,
                        'packet_count': packet_count,
                        'packet_rate': f"{packet_count}/秒",
                        'total_bytes': total_bytes,
                        'avg_packet_size': f"{avg_size:.1f}字节",
                        'unique_src_ips': unique_src_ips,
                        'main_target': top_dst_ip[0] if top_dst_ip else "未知",
                        'protocol_distribution': dict(protocol_counter),
                        'risk_level': '严重' if packet_count > 1000 else '高危',
                        'description': f"{time_key}检测到{attack_type}，速率{packet_count}包/秒"
                    })
        
        # 按包数量排序
        results.sort(key=lambda x: x['packet_count'], reverse=True)
        return results
    
    def detect_abnormal_protocols(self):
        """检测异常协议使用"""
        if not self.packets:
            return []
        
        # 统计协议分布
        protocol_counter = Counter([p.get('protocol', '未知') for p in self.packets])
        total_packets = len(self.packets)
        
        # 定义正常协议
        normal_protocols = {'TCP', 'UDP', 'ICMP', 'ARP', 'HTTP', 'HTTPS', 'DNS'}
        
        anomalies = []
        
        for protocol, count in protocol_counter.items():
            percentage = (count / total_packets) * 100
            
            # 检查异常
            if protocol not in normal_protocols and protocol != '未知':
                # 未知协议
                anomalies.append({
                    'protocol': protocol,
                    'count': count,
                    'percentage': f"{percentage:.1f}%",
                    'severity': '中危',
                    'description': f"检测到非常见协议: {protocol}，占比{percentage:.1f}%",
                    'recommendation': "检查是否为合法应用或潜在恶意流量"
                })
            
            elif protocol == 'ICMP' and percentage > 30:
                # ICMP占比过高
                anomalies.append({
                    'protocol': protocol,
                    'count': count,
                    'percentage': f"{percentage:.1f}%",
                    'severity': '低危',
                    'description': f"ICMP流量占比过高({percentage:.1f}%)",
                    'recommendation': "可能为正常ping扫描或ICMP洪水攻击"
                })
        
        return anomalies
    
    def detect_suspicious_patterns(self):
        """检测可疑行为模式"""
        if not self.packets:
            return []
        
        patterns = []
        
        # 检测短时间内的ARP请求风暴
        arp_requests = [p for p in self.packets if p.get('protocol') == 'ARP']
        if len(arp_requests) > 50:
            # 检查时间分布
            if len(arp_requests) > 0:
                patterns.append({
                    'pattern_type': 'ARP风暴',
                    'count': len(arp_requests),
                    'severity': '中危',
                    'description': f"检测到{len(arp_requests)}个ARP请求，可能为ARP欺骗攻击",
                    'recommendation': "检查网络是否存在ARP欺骗"
                })
        
        # 检测到非标准端口的HTTP/HTTPS
        http_https_packets = [p for p in self.packets if p.get('application') in ['HTTP', 'HTTPS']]
        for packet in http_https_packets:
            dst_port = packet.get('dst_port', 0)
            if dst_port not in [80, 443, 8080, 8443]:
                patterns.append({
                    'pattern_type': '非常规HTTP端口',
                    'port': dst_port,
                    'src_ip': packet.get('src_ip', '未知'),
                    'severity': '低危',
                    'description': f"在非常规端口{dst_port}检测到HTTP/HTTPS流量",
                    'recommendation': "检查是否为代理或隧道流量"
                })
                break
        
        # 检测DNS隧道特征
        dns_packets = [p for p in self.packets if p.get('application') == 'DNS']
        if dns_packets:
            long_query_count = sum(1 for p in dns_packets if 'dns_query' in p and len(p['dns_query']) > 50)
            if long_query_count > 10:
                patterns.append({
                    'pattern_type': 'DNS隧道特征',
                    'count': long_query_count,
                    'severity': '高危',
                    'description': f"检测到{long_query_count}个超长DNS查询，疑似DNS隧道",
                    'recommendation': "检查DNS流量是否被用于数据泄露"
                })
        
        return patterns
    
    def generate_security_report(self):
        """生成完整安全报告"""
        report = {
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_packets_analyzed': len(self.packets),
            'port_scans': self.detect_port_scan(),
            'ddos_attacks': self.detect_ddos(),
            'abnormal_protocols': self.detect_abnormal_protocols(),
            'suspicious_patterns': self.detect_suspicious_patterns(),
            'summary': {}
        }
        
        # 生成摘要
        total_threats = (len(report['port_scans']) + len(report['ddos_attacks']) + 
                        len(report['abnormal_protocols']) + len(report['suspicious_patterns']))
        
        if total_threats == 0:
            report['summary']['overall_risk'] = '安全'
            report['summary']['assessment'] = '未检测到明显安全威胁'
        elif total_threats <= 2:
            report['summary']['overall_risk'] = '低风险'
            report['summary']['assessment'] = '检测到少量可疑活动，建议监控'
        elif total_threats <= 5:
            report['summary']['overall_risk'] = '中风险'
            report['summary']['assessment'] = '检测到多个可疑活动，需要进一步调查'
        else:
            report['summary']['overall_risk'] = '高风险'
            report['summary']['assessment'] = '检测到大量可疑活动，建议立即采取行动'
        
        report['summary']['total_threats'] = total_threats
        
        return report


# 便捷函数
def anonymize_ip(ip_address, method='mask'):
    """便捷函数：匿名化IP地址"""
    return PrivacyUtils.anonymize_ip(ip_address, method)

def detect_port_scan(packets, threshold=10):
    """便捷函数：检测端口扫描"""
    detector = AnomalyDetector(packets)
    return detector.detect_port_scan(threshold=threshold)

def detect_ddos(packets, packet_threshold=100):
    """便捷函数：检测DDoS攻击"""
    detector = AnomalyDetector(packets)
    return detector.detect_ddos(packet_threshold=packet_threshold)

def anonymize_packets(packets, ip_method='mask'):
    """便捷函数：匿名化数据包"""
    return PrivacyUtils.anonymize_packets(packets, ip_method=ip_method)

def generate_privacy_report(packets):
    """便捷函数：生成隐私报告"""
    return PrivacyUtils.generate_privacy_report(packets)


# 测试函数
def test_utils():
    """测试工具函数"""
    print("=== 工具模块测试 ===")
    
    # 测试数据
    test_packets = [
        {
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'src_mac': '00:11:22:33:44:55',
            'dst_mac': '66:77:88:99:aa:bb',
            'protocol': 'TCP',
            'src_port': 12345,
            'dst_port': 80,
            'length': 1500,
            'application': 'HTTP',
            'http_host': 'example.com',
            'timestamp': '12:00:01.123'
        },
        {
            'src_ip': '10.0.0.1',
            'dst_ip': '8.8.8.8',
            'src_mac': 'aa:bb:cc:dd:ee:ff',
            'dst_mac': '00:11:22:33:44:55',
            'protocol': 'UDP',
            'src_port': 54321,
            'dst_port': 53,
            'length': 512,
            'application': 'DNS',
            'timestamp': '12:00:02.456'
        }
    ]
    
    # 测试匿名化
    print("1. 测试IP匿名化:")
    print(f"   原始: 192.168.1.100 -> {anonymize_ip('192.168.1.100')}")
    
    print("\n2. 测试数据包匿名化:")
    anonymized = anonymize_packets(test_packets)
    print(f"   匿名化后第一个包: {anonymized[0]['src_ip']} -> {anonymized[0]['dst_ip']}")
    
    print("\n3. 测试隐私报告:")
    report = generate_privacy_report(test_packets)
    print(f"   风险等级: {report['risk_level']}")
    
    print("\n4. 测试异常检测:")
    detector = AnomalyDetector(test_packets)
    scans = detector.detect_port_scan()
    print(f"   端口扫描检测结果: {len(scans)} 个")
    
    print("\n✅ utils.py 测试完成")
    
    return True

if __name__ == "__main__":
    test_utils()
