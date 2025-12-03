# packet_capture.py - 完整核心版
"""
packet_capture.py - 核心抓包模块
"""

import json
import time
from datetime import datetime
from collections import defaultdict, Counter
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR
import scapy.all as scapy

class PacketCapture:
    def __init__(self, interface=None):
        self.packets = []  # 存储数据包信息
        self.is_capturing = False
        self.capture_count = 0
        self.interface = interface
        self.callbacks = []
        self._stop_flag = False
    
    def start_capture(self, count=50, filter_str="", timeout=30):
        """开始捕获数据包（带超时保护）"""
        print(f"[INFO] 开始抓包: 数量={count}, 过滤={filter_str or '无'}")
        self.packets.clear()
        self.capture_count = 0
        self.is_capturing = True
        self._stop_flag = False
        
        try:
            def packet_handler(packet):
                if self._stop_flag or not self.is_capturing:
                    return False
                
                self.capture_count += 1
                packet_info = self._extract_packet_info(packet, self.capture_count)
                self.packets.append(packet_info)
                
                # 调用回调（GUI更新）
                for callback in self.callbacks:
                    try:
                        callback(packet_info)
                    except Exception as e:
                        print(f"[ERROR] 回调错误: {e}")
                
                return self.capture_count < count
            
            # 抓包参数
            sniff_params = {
                'prn': packet_handler,
                'store': False,
                'count': count,
                'timeout': timeout
            }
            
            if self.interface:
                sniff_params['iface'] = self.interface
            if filter_str:
                sniff_params['filter'] = filter_str
            
            # 开始抓包
            sniff(**sniff_params)
            self.is_capturing = False
            print(f"[SUCCESS] 抓包完成！捕获 {len(self.packets)} 个包")
            return True
            
        except Exception as e:
            print(f"[ERROR] 抓包失败: {e}")
            self.is_capturing = False
            return False
    
    def stop_capture(self):
        """停止抓包"""
        self._stop_flag = True
        self.is_capturing = False
        print("[INFO] 停止抓包")
    
    def _extract_packet_info(self, packet, packet_no):
        """提取数据包关键信息"""
        packet_info = {
            'no': packet_no,
            'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'unix_time': time.time(),
            'length': len(packet),
            'summary': packet.summary()
        }
        
        # 以太网层
        if Ether in packet:
            eth = packet[Ether]
            packet_info.update({
                'src_mac': eth.src,
                'dst_mac': eth.dst
            })
        
        # IP层
        if IP in packet:
            ip = packet[IP]
            packet_info.update({
                'src_ip': ip.src,
                'dst_ip': ip.dst,
                'ttl': ip.ttl
            })
            
            # TCP
            if TCP in packet:
                tcp = packet[TCP]
                packet_info.update({
                    'protocol': 'TCP',
                    'src_port': tcp.sport,
                    'dst_port': tcp.dport,
                    'tcp_flags': self._parse_tcp_flags(tcp.flags)
                })
                
                # HTTP检测
                if tcp.dport == 80 or tcp.sport == 80:
                    packet_info['application'] = 'HTTP'
                    self._parse_http(packet, packet_info)
                elif tcp.dport == 443 or tcp.sport == 443:
                    packet_info['application'] = 'HTTPS'
            
            # UDP
            elif UDP in packet:
                udp = packet[UDP]
                packet_info.update({
                    'protocol': 'UDP',
                    'src_port': udp.sport,
                    'dst_port': udp.dport
                })
                
                # DNS检测
                if udp.dport == 53 or udp.sport == 53:
                    packet_info['application'] = 'DNS'
                    self._parse_dns(packet, packet_info)
            
            # ICMP
            elif ICMP in packet:
                icmp = packet[ICMP]
                packet_info.update({
                    'protocol': 'ICMP',
                    'icmp_type': icmp.type,
                    'icmp_code': icmp.code
                })
                packet_info['application'] = 'ICMP'
        
        # ARP
        elif ARP in packet:
            arp = packet[ARP]
            packet_info.update({
                'protocol': 'ARP',
                'src_ip': arp.psrc,
                'dst_ip': arp.pdst,
                'src_mac': arp.hwsrc,
                'dst_mac': arp.hwdst
            })
            packet_info['application'] = 'ARP'
        
        return packet_info
    
    def _parse_tcp_flags(self, flags):
        """解析TCP标志位"""
        flag_map = {
            0x01: "FIN", 0x02: "SYN", 0x04: "RST",
            0x08: "PSH", 0x10: "ACK", 0x20: "URG"
        }
        flag_names = [name for bit, name in flag_map.items() if flags & bit]
        return ', '.join(flag_names) if flag_names else '无'
    
    def _parse_http(self, packet, packet_info):
        """解析HTTP协议"""
        try:
            if HTTPRequest in packet:
                http = packet[HTTPRequest]
                packet_info['http_method'] = http.Method.decode('utf-8', errors='ignore') if hasattr(http.Method, 'decode') else str(http.Method)
                packet_info['http_path'] = http.Path.decode('utf-8', errors='ignore') if hasattr(http.Path, 'decode') else str(http.Path)
            elif HTTPResponse in packet:
                http = packet[HTTPResponse]
                packet_info['http_status'] = http.Status_Code
        except:
            pass
    
    def _parse_dns(self, packet, packet_info):
        """解析DNS协议"""
        try:
            if DNS in packet:
                dns = packet[DNS]
                if DNSQR in dns:
                    packet_info['dns_query'] = str(dns[DNSQR].qname).rstrip('.')
                if DNSRR in dns and dns.ancount > 0:
                    packet_info['dns_answer'] = str(dns.an[0].rdata)
        except:
            pass
    
    def register_callback(self, callback):
        """注册回调函数"""
        if callback not in self.callbacks:
            self.callbacks.append(callback)
    
    def get_statistics(self):
        """获取基本统计"""
        if not self.packets:
            return {'total_packets': 0, 'total_bytes': 0}
        
        stats = {
            'total_packets': len(self.packets),
            'total_bytes': sum(p['length'] for p in self.packets),
            'protocols': Counter([p.get('protocol', '未知') for p in self.packets])
        }
        return stats
    
    def save_to_file(self, filename):
        """保存到JSON文件"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump({
                    'metadata': {
                        'capture_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'total_packets': len(self.packets),
                        'interface': self.interface or '默认'
                    },
                    'packets': self.packets
                }, f, indent=2, ensure_ascii=False)
            print(f"[SUCCESS] 保存到 {filename}")
            return True
        except Exception as e:
            print(f"[ERROR] 保存失败: {e}")
            return False
    
    def load_from_file(self, filename):
        """从文件加载"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.packets = data.get('packets', [])
            print(f"[SUCCESS] 从 {filename} 加载了 {len(self.packets)} 个包")
            return True
        except Exception as e:
            print(f"[ERROR] 加载失败: {e}")
            return False
    
    def get_available_interfaces(self):
        """获取可用网络接口"""
        try:
            from scapy.all import get_if_list
            interfaces = get_if_list()
            return interfaces if interfaces else ['自动选择']
        except:
            return ['自动选择', 'eth0', 'wlan0', 'lo']

# 测试函数
def test():
    """简单测试"""
    print("=== 抓包模块测试 ===")
    capture = PacketCapture()
    
    print("可用接口:", capture.get_available_interfaces())
    
    def print_callback(packet):
        print(f"[{packet['timestamp']}] {packet.get('src_ip', '?')} -> {packet.get('dst_ip', '?')} [{packet.get('protocol', '?')}]")
    
    capture.register_callback(print_callback)
    
    print("\n开始抓包测试（3个包）...")
    print("请运行: ping 127.0.0.1 -n 3")
    
    success = capture.start_capture(count=3, filter_str="icmp", timeout=10)
    
    if success:
        print(f"\n捕获 {len(capture.packets)} 个包")
        stats = capture.get_statistics()
        print(f"统计: {stats['total_packets']}包, {stats['total_bytes']}字节")

if __name__ == "__main__":
    test()