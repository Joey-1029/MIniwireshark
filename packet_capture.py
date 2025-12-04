# packet_capture.py - 完整修复版本
"""
packet_capture.py - 核心抓包模块
修复了无法捕获ICMP/UDP等非TCP流量的bug
"""

import json
import time
import sys
from datetime import datetime
from collections import defaultdict, Counter
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether, Raw, IPv6
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
        self._debug = False  # 调试模式开关
    
    def start_capture(self, count=50, filter_str="", timeout=30):
        """开始捕获数据包（修复版本）"""
        print(f"[INFO] 开始抓包: 数量={count}, 过滤={filter_str or '无'}, 超时={timeout}秒")
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
            
            # 抓包参数 - 关键修复：正确处理过滤条件
            sniff_params = {
                'prn': packet_handler,
                'store': False,
                'count': count,
                'timeout': timeout,
                'promisc': False  # 普通模式
            }
            
            # 设置接口
            if self.interface and self.interface != '自动选择':
                sniff_params['iface'] = self.interface
                print(f"[INFO] 使用接口: {self.interface}")
            else:
                print("[INFO] 自动选择接口")
            
            # 设置过滤条件 - 关键修复：为空时不设置filter参数
            if filter_str and filter_str.strip():
                sniff_params['filter'] = filter_str.strip()
                print(f"[INFO] 使用过滤: {filter_str}")
            else:
                print("[INFO] 无过滤条件，捕获所有流量")
                # 不设置filter参数，让scapy捕获所有流量
            
            # 开始抓包
            print("[INFO] 正在抓包...")
            sniff(**sniff_params)
            
            self.is_capturing = False
            
            if self._stop_flag:
                print("[INFO] 抓包被用户停止")
            else:
                print(f"[SUCCESS] 抓包完成！捕获 {len(self.packets)} 个包")
                
            return True
            
        except Exception as e:
            print(f"[ERROR] 抓包失败: {e}")
            import traceback
            traceback.print_exc()
            self.is_capturing = False
            return False
    
    def stop_capture(self):
        """停止抓包"""
        self._stop_flag = True
        self.is_capturing = False
        print("[INFO] 停止抓包信号已发送")
    
    def _extract_packet_info(self, packet, packet_no):
        """提取数据包关键信息（修复版本）"""
        if self._debug:
            print(f"\n[DEBUG] 处理包 #{packet_no}: {packet.summary()}")
        
        packet_info = {
            'no': packet_no,
            'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'unix_time': time.time(),
            'length': len(packet),
            'summary': packet.summary()[:100]  # 限制摘要长度
        }
        
        # ===== 以太网层 =====
        if Ether in packet:
            eth = packet[Ether]
            packet_info.update({
                'src_mac': eth.src,
                'dst_mac': eth.dst
            })
            if self._debug:
                print(f"[DEBUG] MAC: {eth.src} -> {eth.dst}")
        
        # ===== IP层（IPv4） =====
        if IP in packet:
            ip = packet[IP]
            packet_info.update({
                'src_ip': ip.src,
                'dst_ip': ip.dst,
                'ttl': ip.ttl,
                'version': 4
            })
            
            if self._debug:
                print(f"[DEBUG] IPv4: {ip.src} -> {ip.dst}, 协议号={ip.proto}")
            
            # 根据IP协议号判断传输层协议
            # 1=ICMP, 2=IGMP, 6=TCP, 17=UDP, 47=GRE, 50=ESP, 51=AH, 89=OSPF
            if ip.proto == 6:  # TCP
                if TCP in packet:
                    tcp = packet[TCP]
                    packet_info.update({
                        'protocol': 'TCP',
                        'src_port': tcp.sport,
                        'dst_port': tcp.dport,
                        'tcp_flags': self._parse_tcp_flags(tcp.flags),
                        'seq_num': tcp.seq if hasattr(tcp, 'seq') else '',
                        'ack_num': tcp.ack if hasattr(tcp, 'ack') else ''
                    })
                    
                    # 应用层检测
                    if tcp.dport == 80 or tcp.sport == 80:
                        packet_info['application'] = 'HTTP'
                        self._parse_http(packet, packet_info)
                    elif tcp.dport == 443 or tcp.sport == 443:
                        packet_info['application'] = 'HTTPS'
                    elif tcp.dport == 21 or tcp.sport == 21:
                        packet_info['application'] = 'FTP'
                    elif tcp.dport == 22 or tcp.sport == 22:
                        packet_info['application'] = 'SSH'
                    elif tcp.dport == 23 or tcp.sport == 23:
                        packet_info['application'] = 'Telnet'
                    elif tcp.dport == 25 or tcp.sport == 25:
                        packet_info['application'] = 'SMTP'
                    elif tcp.dport == 53 or tcp.sport == 53:
                        packet_info['application'] = 'DNS'
                        self._parse_dns(packet, packet_info)
                    elif tcp.dport == 110 or tcp.sport == 110:
                        packet_info['application'] = 'POP3'
                    elif tcp.dport == 143 or tcp.sport == 143:
                        packet_info['application'] = 'IMAP'
                    elif tcp.dport == 993 or tcp.sport == 993:
                        packet_info['application'] = 'IMAPS'
                    elif tcp.dport == 995 or tcp.sport == 995:
                        packet_info['application'] = 'POP3S'
                    
                    if self._debug:
                        print(f"[DEBUG] TCP端口: {tcp.sport} -> {tcp.dport}")
                else:
                    packet_info['protocol'] = 'TCP(no-layer)'
            
            elif ip.proto == 17:  # UDP
                if UDP in packet:
                    udp = packet[UDP]
                    packet_info.update({
                        'protocol': 'UDP',
                        'src_port': udp.sport,
                        'dst_port': udp.dport
                    })
                    
                    # 应用层检测
                    if udp.dport == 53 or udp.sport == 53:
                        packet_info['application'] = 'DNS'
                        self._parse_dns(packet, packet_info)
                    elif udp.dport == 67 or udp.dport == 68 or udp.sport == 67 or udp.sport == 68:
                        packet_info['application'] = 'DHCP'
                    elif udp.dport == 123 or udp.sport == 123:
                        packet_info['application'] = 'NTP'
                    elif udp.dport == 161 or udp.sport == 161:
                        packet_info['application'] = 'SNMP'
                    elif udp.dport == 162 or udp.sport == 162:
                        packet_info['application'] = 'SNMP-trap'
                    elif udp.dport == 137 or udp.sport == 137:
                        packet_info['application'] = 'NetBIOS'
                    elif udp.dport == 138 or udp.sport == 138:
                        packet_info['application'] = 'NetBIOS-dgm'
                    elif udp.dport == 1900 or udp.sport == 1900:
                        packet_info['application'] = 'SSDP'
                    
                    if self._debug:
                        print(f"[DEBUG] UDP端口: {udp.sport} -> {udp.dport}")
                else:
                    packet_info['protocol'] = 'UDP(no-layer)'
            
            elif ip.proto == 1:  # ICMP
                if ICMP in packet:
                    icmp = packet[ICMP]
                    packet_info.update({
                        'protocol': 'ICMP',
                        'icmp_type': icmp.type,
                        'icmp_code': icmp.code,
                        'icmp_id': icmp.id if hasattr(icmp, 'id') else '',
                        'icmp_seq': icmp.seq if hasattr(icmp, 'seq') else ''
                    })
                    packet_info['application'] = 'ICMP'
                    
                    if self._debug:
                        print(f"[DEBUG] ICMP类型: {icmp.type}, 代码: {icmp.code}")
                else:
                    packet_info['protocol'] = 'ICMP(no-layer)'
            
            elif ip.proto == 2:  # IGMP
                packet_info['protocol'] = 'IGMP'
                packet_info['application'] = 'IGMP'
            
            elif ip.proto == 89:  # OSPF
                packet_info['protocol'] = 'OSPF'
                packet_info['application'] = 'OSPF'
            
            else:
                # 其他IP协议
                packet_info['protocol'] = f'IP-{ip.proto}'
                if self._debug:
                    print(f"[DEBUG] 其他IP协议: {ip.proto}")
        
        # ===== IPv6层 =====
        elif IPv6 in packet:
            ipv6 = packet[IPv6]
            packet_info.update({
                'src_ip': ipv6.src,
                'dst_ip': ipv6.dst,
                'version': 6,
                'protocol': 'IPv6'
            })
            
            # IPv6的下一头部相当于IPv4的协议号
            if hasattr(ipv6, 'nh'):
                packet_info['ip_proto'] = ipv6.nh
                if self._debug:
                    print(f"[DEBUG] IPv6: {ipv6.src} -> {ipv6.dst}, 下一头部={ipv6.nh}")
        
        # ===== ARP层 =====
        elif ARP in packet:
            arp = packet[ARP]
            packet_info.update({
                'protocol': 'ARP',
                'src_ip': arp.psrc,
                'dst_ip': arp.pdst,
                'src_mac': arp.hwsrc,
                'dst_mac': arp.hwdst,
                'op': arp.op  # 1=请求, 2=回复
            })
            packet_info['application'] = 'ARP'
            
            if self._debug:
                op_map = {1: '请求', 2: '回复'}
                op_str = op_map.get(arp.op, f'未知({arp.op})')
                print(f"[DEBUG] ARP {op_str}: {arp.psrc}({arp.hwsrc}) -> {arp.pdst}")
        
        # ===== 其他非IP协议 =====
        else:
            # 检查是否为其他常见协议
            if packet.haslayer('STP'):  # 生成树协议
                packet_info['protocol'] = 'STP'
                packet_info['application'] = 'STP'
            elif packet.haslayer('LLC'):  # 逻辑链路控制
                packet_info['protocol'] = 'LLC'
                packet_info['application'] = 'LLC'
            else:
                # 无法识别的协议
                packet_info['protocol'] = '未知'
                if self._debug:
                    print(f"[DEBUG] 无法识别协议，层: {packet.layers()}")
        
        # 确保protocol字段存在
        if 'protocol' not in packet_info:
            packet_info['protocol'] = '未知'
        
        if self._debug:
            print(f"[DEBUG] 最终协议: {packet_info.get('protocol')}")
        
        return packet_info
    
    def _parse_tcp_flags(self, flags):
        """解析TCP标志位"""
        flag_map = {
            0x01: "FIN", 0x02: "SYN", 0x04: "RST",
            0x08: "PSH", 0x10: "ACK", 0x20: "URG",
            0x40: "ECE", 0x80: "CWR"
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
                
                # 提取其他HTTP头
                if hasattr(http, 'Host'):
                    packet_info['http_host'] = http.Host.decode('utf-8', errors='ignore') if hasattr(http.Host, 'decode') else str(http.Host)
                if hasattr(http, 'User_Agent'):
                    packet_info['http_user_agent'] = http.User_Agent.decode('utf-8', errors='ignore') if hasattr(http.User_Agent, 'decode') else str(http.User_Agent)
                if hasattr(http, 'Accept'):
                    packet_info['http_accept'] = http.Accept.decode('utf-8', errors='ignore') if hasattr(http.Accept, 'decode') else str(http.Accept)
                
            elif HTTPResponse in packet:
                http = packet[HTTPResponse]
                packet_info['http_status'] = http.Status_Code
                packet_info['http_reason'] = http.Reason_Phrase.decode('utf-8', errors='ignore') if hasattr(http.Reason_Phrase, 'decode') else str(http.Reason_Phrase)
                
                if hasattr(http, 'Server'):
                    packet_info['http_server'] = http.Server.decode('utf-8', errors='ignore') if hasattr(http.Server, 'decode') else str(http.Server)
                if hasattr(http, 'Content_Type'):
                    packet_info['http_content_type'] = http.Content_Type.decode('utf-8', errors='ignore') if hasattr(http.Content_Type, 'decode') else str(http.Content_Type)
                    
        except Exception as e:
            if self._debug:
                print(f"[DEBUG] HTTP解析错误: {e}")
    
    def _parse_dns(self, packet, packet_info):
        """解析DNS协议"""
        try:
            if DNS in packet:
                dns = packet[DNS]
                
                # DNS事务ID
                if hasattr(dns, 'id'):
                    packet_info['dns_id'] = dns.id
                
                # 查询标志
                if hasattr(dns, 'qr'):
                    packet_info['dns_qr'] = '响应' if dns.qr else '查询'
                
                # 查询类型
                if hasattr(dns, 'qdcount') and dns.qdcount > 0 and DNSQR in dns:
                    dnsqr = dns[DNSQR]
                    packet_info['dns_query'] = str(dnsqr.qname).rstrip('.')
                    if hasattr(dnsqr, 'qtype'):
                        qtype_map = {1: 'A', 2: 'NS', 5: 'CNAME', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA'}
                        qtype = qtype_map.get(dnsqr.qtype, str(dnsqr.qtype))
                        packet_info['dns_qtype'] = qtype
                
                # 回答记录
                if hasattr(dns, 'ancount') and dns.ancount > 0 and DNSRR in dns:
                    answers = []
                    for i in range(min(dns.ancount, 3)):  # 最多取前3个回答
                        try:
                            answer = dns.an[i]
                            if hasattr(answer, 'rdata'):
                                answers.append(str(answer.rdata))
                        except:
                            pass
                    if answers:
                        packet_info['dns_answer'] = ', '.join(answers)
                
                # 响应码
                if hasattr(dns, 'rcode'):
                    rcode_map = {0: 'NoError', 1: 'FormErr', 2: 'ServFail', 3: 'NXDomain', 4: 'NotImp', 5: 'Refused'}
                    packet_info['dns_rcode'] = rcode_map.get(dns.rcode, f'未知({dns.rcode})')
                    
        except Exception as e:
            if self._debug:
                print(f"[DEBUG] DNS解析错误: {e}")
    
    def register_callback(self, callback):
        """注册回调函数"""
        if callback not in self.callbacks:
            self.callbacks.append(callback)
            if self._debug:
                print(f"[DEBUG] 注册回调，总数: {len(self.callbacks)}")
    
    def get_statistics(self):
        """获取基本统计"""
        if not self.packets:
            return {'total_packets': 0, 'total_bytes': 0}
        
        # 协议统计
        protocol_counter = Counter()
        ip_counter = Counter()
        port_counter = Counter()
        
        for packet in self.packets:
            protocol = packet.get('protocol', '未知')
            protocol_counter[protocol] += 1
            
            src_ip = packet.get('src_ip')
            if src_ip and src_ip != 'N/A':
                ip_counter[src_ip] += 1
        
        # 时间范围
        time_range = "N/A"
        if self.packets:
            first_time = min(p.get('unix_time', 0) for p in self.packets)
            last_time = max(p.get('unix_time', 0) for p in self.packets)
            if first_time and last_time:
                duration = last_time - first_time
                time_range = f"{duration:.2f}秒"
        
        stats = {
            'total_packets': len(self.packets),
            'total_bytes': sum(p.get('length', 0) for p in self.packets),
            'protocol_distribution': dict(protocol_counter),
            'unique_src_ips': len(set(p.get('src_ip') for p in self.packets if p.get('src_ip') and p.get('src_ip') != 'N/A')),
            'unique_dst_ips': len(set(p.get('dst_ip') for p in self.packets if p.get('dst_ip') and p.get('dst_ip') != 'N/A')),
            'time_range': time_range,
            'avg_packet_size': sum(p.get('length', 0) for p in self.packets) / len(self.packets) if self.packets else 0
        }
        
        # Top 10源IP
        if ip_counter:
            top_ips = dict(sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:10])
            stats['top_src_ips'] = top_ips
        
        return stats
    
    def save_to_file(self, filename):
        """保存到JSON文件"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump({
                    'metadata': {
                        'capture_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'total_packets': len(self.packets),
                        'interface': self.interface or '默认',
                        'software': '迷你Wireshark v1.0'
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
            
            if not interfaces:
                print("[WARN] 未找到网络接口，返回默认列表")
                # 常见接口名称
                default_interfaces = ['自动选择', 'eth0', 'eth1', 'wlan0', 'wlan1', 'en0', 'en1', 'lo']
                return [iface for iface in default_interfaces]
            
            # 添加"自动选择"选项
            all_interfaces = ['自动选择'] + list(interfaces)
            print(f"[INFO] 发现 {len(interfaces)} 个网络接口")
            
            return all_interfaces
            
        except Exception as e:
            print(f"[ERROR] 获取接口失败: {e}")
            return ['自动选择', 'eth0', 'wlan0', 'lo']
    
    def enable_debug(self):
        """启用调试模式"""
        self._debug = True
        print("[DEBUG] 调试模式已启用")
    
    def disable_debug(self):
        """禁用调试模式"""
        self._debug = False
        print("[DEBUG] 调试模式已禁用")


# ===== 测试函数 =====
def comprehensive_test():
    """全面测试函数"""
    print("=" * 60)
    print("PacketCapture 模块全面测试")
    print("=" * 60)
    
    # 创建实例
    capture = PacketCapture()
    
    # 启用调试
    capture.enable_debug()
    
    # 测试接口获取
    print("\n1. 测试接口获取...")
    interfaces = capture.get_available_interfaces()
    print(f"可用接口: {interfaces}")
    
    # 测试回调
    print("\n2. 测试回调注册...")
    
    def test_callback(packet_info):
        print(f"  回调收到包#{packet_info['no']}: {packet_info.get('protocol')} {packet_info.get('src_ip', 'N/A')} -> {packet_info.get('dst_ip', 'N/A')}")
    
    capture.register_callback(test_callback)
    
    # 测试抓包
    print("\n3. 测试抓包功能...")
    print("   请在另一个窗口生成以下流量:")
    print("   - ping 8.8.8.8 -n 2 (ICMP)")
    print("   - nslookup google.com (DNS/UDP)")
    print("   - 访问一个网站 (TCP/HTTP)")
    print("   - ping 127.0.0.1 -n 1 (本地ICMP)")
    print("\n   开始抓包（5个包，10秒超时）...")
    
    import threading
    import time as ttime
    
    def run_capture():
        success = capture.start_capture(count=5, filter_str="", timeout=10)
        if success:
            print(f"\n抓包完成！捕获 {len(capture.packets)} 个包")
            
            # 统计
            if capture.packets:
                print("\n捕获统计:")
                print(f"总包数: {len(capture.packets)}")
                
                protocols = {}
                for p in capture.packets:
                    proto = p.get('protocol', '未知')
                    protocols[proto] = protocols.get(proto, 0) + 1
                
                print("协议分布:")
                for proto, count in protocols.items():
                    print(f"  {proto}: {count}")
                
                # 显示样本
                print("\n样本包（前2个）:")
                for i, p in enumerate(capture.packets[:2]):
                    print(f"  包#{i+1}: {p.get('protocol')} {p.get('src_ip', 'N/A')}:{p.get('src_port', '')} -> {p.get('dst_ip', 'N/A')}:{p.get('dst_port', '')}")
        else:
            print("\n抓包失败")
    
    # 在新线程中运行
    thread = threading.Thread(target=run_capture)
    thread.daemon = True
    thread.start()
    
    # 等待完成
    thread.join(timeout=15)
    
    if thread.is_alive():
        print("\n抓包超时，正在停止...")
        capture.stop_capture()
        ttime.sleep(1)
    
    # 测试保存/加载
    print("\n4. 测试保存功能...")
    if capture.packets:
        test_file = "test_capture.json"
        if capture.save_to_file(test_file):
            print(f"  保存成功: {test_file}")
            
            # 测试加载
            capture2 = PacketCapture()
            if capture2.load_from_file(test_file):
                print(f"  加载成功: {len(capture2.packets)} 个包")
            else:
                print("  加载失败")
            
            # 清理测试文件
            import os
            if os.path.exists(test_file):
                os.remove(test_file)
                print(f"  清理测试文件: {test_file}")
        else:
            print("  保存失败")
    
    # 禁用调试
    capture.disable_debug()
    
    print("\n" + "=" * 60)
    print("测试完成！")
    print("=" * 60)
    
    # 等待用户确认
    input("\n按Enter退出测试...")


if __name__ == "__main__":
    print("PacketCapture模块 - 修复版本 v1.1")
    print("修复了无法捕获ICMP/UDP等非TCP流量的问题")
    print("-" * 60)
    
    # 检查运行权限
    import platform
    if platform.system() == "Windows":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if not is_admin:
                print("⚠️ 警告: 建议以管理员身份运行以获得最佳抓包效果")
                print("在PowerShell中右键选择'以管理员身份运行'")
        except:
            pass
    
    # 运行测试
    comprehensive_test()