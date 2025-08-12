import os
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
import ipaddress
import socket
import re

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, ICMP, ARP
    try:
        from scapy.layers.http import HTTPRequest, HTTPResponse
        HTTP_AVAILABLE = True
    except ImportError:
        HTTP_AVAILABLE = False
        HTTPRequest = None
        HTTPResponse = None
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    HTTP_AVAILABLE = False

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

class NetworkTrafficAnalyzer:
    """
    Advanced network traffic analyzer for PCAP files
    """
    
    def __init__(self):
        self.suspicious_ports = {
            22: 'SSH', 23: 'Telnet', 135: 'RPC', 139: 'NetBIOS', 445: 'SMB',
            1433: 'MSSQL', 3389: 'RDP', 5432: 'PostgreSQL', 3306: 'MySQL'
        }
        
        self.common_ports = {
            20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP',
            110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
            587: 'SMTP-TLS', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        
        self.analysis_results = {
            'total_packets': 0,
            'duration': 0,
            'protocols': defaultdict(int),
            'ip_activity': defaultdict(lambda: {
                'packets_sent': 0,
                'packets_received': 0,
                'bytes_sent': 0,
                'bytes_received': 0,
                'domains': set(),
                'ports_accessed': set(),
                'sessions': [],
                'suspicious_activity': [],
                'geolocation': None
            }),
            'top_talkers': [],
            'anomalies': [],
            'security_issues': [],
            'port_analysis': defaultdict(int),
            'dns_queries': defaultdict(int),
            'http_requests': [],
            'connection_attempts': defaultdict(int)
        }
        
        # Initialize GeoIP database if available
        self.geoip_reader = None
        if GEOIP_AVAILABLE:
            self._init_geoip()
    
    def _init_geoip(self):
        """Initialize GeoIP database"""
        # Common GeoIP database locations
        possible_paths = [
            '/usr/share/GeoIP/GeoLite2-City.mmdb',
            '/opt/GeoIP/GeoLite2-City.mmdb',
            './GeoLite2-City.mmdb',
            'GeoLite2-City.mmdb'
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                try:
                    self.geoip_reader = geoip2.database.Reader(path)
                    break
                except Exception:
                    continue
    
    def analyze_pcap(self, pcap_path: str, progress_callback: Optional[callable] = None) -> Dict[str, Any]:
        """Analyze PCAP file and generate comprehensive report"""
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for PCAP analysis. Install with: pip install scapy")
        
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        
        try:
            # Load PCAP file
            packets = rdpcap(pcap_path)
            total_packets = len(packets)
            self.analysis_results['total_packets'] = total_packets
            
            if total_packets == 0:
                return self.analysis_results
            
            # Calculate duration
            first_packet_time = packets[0].time
            last_packet_time = packets[-1].time
            self.analysis_results['duration'] = last_packet_time - first_packet_time
            
            # Process packets
            for i, packet in enumerate(packets):
                if progress_callback:
                    progress_callback(i + 1, total_packets, f"Analyzing packet {i+1}")
                
                self._analyze_packet(packet)
            
            # Post-processing analysis
            self._detect_anomalies()
            self._identify_top_talkers()
            self._analyze_security_risks()
            
            return dict(self.analysis_results)
            
        except Exception as e:
            raise Exception(f"Error analyzing PCAP file: {str(e)}")
    
    def _analyze_packet(self, packet):
        """Analyze individual packet"""
        # Protocol analysis
        if IP in packet:
            self._analyze_ip_packet(packet)
        
        if TCP in packet:
            self._analyze_tcp_packet(packet)
        
        if UDP in packet:
            self._analyze_udp_packet(packet)
        
        if DNS in packet:
            self._analyze_dns_packet(packet)
        
        if HTTP_AVAILABLE and (packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse)):
            self._analyze_http_packet(packet)
        
        if ICMP in packet:
            self.analysis_results['protocols']['ICMP'] += 1
        
        if ARP in packet:
            self.analysis_results['protocols']['ARP'] += 1
    
    def _analyze_ip_packet(self, packet):
        """Analyze IP layer"""
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        packet_size = len(packet)
        
        # Update IP activity
        self.analysis_results['ip_activity'][src_ip]['packets_sent'] += 1
        self.analysis_results['ip_activity'][src_ip]['bytes_sent'] += packet_size
        self.analysis_results['ip_activity'][dst_ip]['packets_received'] += 1
        self.analysis_results['ip_activity'][dst_ip]['bytes_received'] += packet_size
        
        # Geolocation analysis
        if self.geoip_reader:
            for ip in [src_ip, dst_ip]:
                if self._is_public_ip(ip) and not self.analysis_results['ip_activity'][ip]['geolocation']:
                    self.analysis_results['ip_activity'][ip]['geolocation'] = self._get_geolocation(ip)
    
    def _analyze_tcp_packet(self, packet):
        """Analyze TCP packet"""
        self.analysis_results['protocols']['TCP'] += 1
        
        if TCP in packet and IP in packet:
            tcp_layer = packet[TCP]
            ip_layer = packet[IP]
            
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            # Port analysis
            self.analysis_results['port_analysis'][dst_port] += 1
            self.analysis_results['ip_activity'][src_ip]['ports_accessed'].add(dst_port)
            
            # Connection attempt tracking
            if tcp_layer.flags == 2:  # SYN flag
                self.analysis_results['connection_attempts'][f"{src_ip}:{dst_ip}:{dst_port}"] += 1
            
            # Detect potential port scanning
            if tcp_layer.flags == 2:  # SYN packets
                self._check_port_scanning(src_ip, dst_ip, dst_port)
    
    def _analyze_udp_packet(self, packet):
        """Analyze UDP packet"""
        self.analysis_results['protocols']['UDP'] += 1
        
        if UDP in packet and IP in packet:
            udp_layer = packet[UDP]
            ip_layer = packet[IP]
            
            dst_port = udp_layer.dport
            src_ip = ip_layer.src
            
            self.analysis_results['port_analysis'][dst_port] += 1
            self.analysis_results['ip_activity'][src_ip]['ports_accessed'].add(dst_port)
    
    def _analyze_dns_packet(self, packet):
        """Analyze DNS packet"""
        self.analysis_results['protocols']['DNS'] += 1
        
        if DNS in packet and packet[DNS].qr == 0:  # DNS query
            query_name = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
            self.analysis_results['dns_queries'][query_name] += 1
            
            # Associate domain with source IP
            if IP in packet:
                src_ip = packet[IP].src
                self.analysis_results['ip_activity'][src_ip]['domains'].add(query_name)
    
    def _analyze_http_packet(self, packet):
        """Analyze HTTP packet"""
        if not HTTP_AVAILABLE:
            return
            
        self.analysis_results['protocols']['HTTP'] += 1
        
        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            try:
                host = http_layer.Host.decode('utf-8') if http_layer.Host else 'Unknown'
                path = http_layer.Path.decode('utf-8') if http_layer.Path else '/'
                method = http_layer.Method.decode('utf-8') if http_layer.Method else 'GET'
                user_agent = http_layer.User_Agent.decode('utf-8') if http_layer.User_Agent else 'Unknown'
            except (AttributeError, UnicodeDecodeError):
                host = 'Unknown'
                path = '/'
                method = 'GET'
                user_agent = 'Unknown'
            
            self.analysis_results['http_requests'].append({
                'timestamp': packet.time,
                'src_ip': packet[IP].src if IP in packet else 'Unknown',
                'host': host,
                'path': path,
                'method': method,
                'user_agent': user_agent
            })
            
            # Associate domain with source IP
            if IP in packet:
                src_ip = packet[IP].src
                self.analysis_results['ip_activity'][src_ip]['domains'].add(host)
    
    def _check_port_scanning(self, src_ip: str, dst_ip: str, dst_port: int):
        """Detect potential port scanning activity"""
        # Count unique ports accessed by source IP to destination IP
        key = f"{src_ip}_{dst_ip}"
        if not hasattr(self, '_port_scan_tracker'):
            self._port_scan_tracker = defaultdict(set)
        
        self._port_scan_tracker[key].add(dst_port)
        
        # Flag as suspicious if accessing many ports
        if len(self._port_scan_tracker[key]) > 10:
            anomaly = {
                'type': 'Port Scanning',
                'description': f"IP {src_ip} accessed {len(self._port_scan_tracker[key])} different ports on {dst_ip}",
                'severity': 'High',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'port_count': len(self._port_scan_tracker[key])
            }
            
            if anomaly not in self.analysis_results['anomalies']:
                self.analysis_results['anomalies'].append(anomaly)
    
    def _detect_anomalies(self):
        """Detect various network anomalies"""
        # High volume connections
        for ip, activity in self.analysis_results['ip_activity'].items():
            total_packets = activity['packets_sent'] + activity['packets_received']
            total_bytes = activity['bytes_sent'] + activity['bytes_received']
            
            if total_packets > 1000:
                self.analysis_results['anomalies'].append({
                    'type': 'High Volume Traffic',
                    'description': f"IP {ip} generated {total_packets} packets ({self._format_bytes(total_bytes)})",
                    'severity': 'Medium',
                    'ip': ip,
                    'packet_count': total_packets,
                    'byte_count': total_bytes
                })
            
            # Suspicious port access
            suspicious_ports_accessed = activity['ports_accessed'].intersection(self.suspicious_ports.keys())
            if suspicious_ports_accessed:
                self.analysis_results['anomalies'].append({
                    'type': 'Suspicious Port Access',
                    'description': f"IP {ip} accessed suspicious ports: {', '.join(map(str, suspicious_ports_accessed))}",
                    'severity': 'High',
                    'ip': ip,
                    'ports': list(suspicious_ports_accessed)
                })
        
        # Excessive DNS queries
        for domain, count in self.analysis_results['dns_queries'].items():
            if count > 50:
                self.analysis_results['anomalies'].append({
                    'type': 'Excessive DNS Queries',
                    'description': f"Domain {domain} queried {count} times",
                    'severity': 'Medium',
                    'domain': domain,
                    'query_count': count
                })
    
    def _identify_top_talkers(self):
        """Identify most active IPs"""
        ip_traffic = []
        
        for ip, activity in self.analysis_results['ip_activity'].items():
            total_packets = activity['packets_sent'] + activity['packets_received']
            total_bytes = activity['bytes_sent'] + activity['bytes_received']
            
            ip_traffic.append({
                'ip': ip,
                'total_packets': total_packets,
                'total_bytes': total_bytes,
                'packets_sent': activity['packets_sent'],
                'packets_received': activity['packets_received'],
                'bytes_sent': activity['bytes_sent'],
                'bytes_received': activity['bytes_received'],
                'domains_accessed': len(activity['domains']),
                'ports_accessed': len(activity['ports_accessed']),
                'geolocation': activity['geolocation']
            })
        
        # Sort by total traffic
        self.analysis_results['top_talkers'] = sorted(
            ip_traffic, key=lambda x: x['total_bytes'], reverse=True
        )[:20]  # Top 20 talkers
    
    def _analyze_security_risks(self):
        """Analyze potential security risks"""
        risks = []
        
        # Unencrypted protocols
        if self.analysis_results['protocols']['HTTP'] > 0:
            risks.append({
                'type': 'Unencrypted HTTP Traffic',
                'description': f"Detected {self.analysis_results['protocols']['HTTP']} HTTP packets",
                'severity': 'Medium',
                'recommendation': 'Consider migrating to HTTPS for better security'
            })
        
        # Suspicious port activity
        for port, count in self.analysis_results['port_analysis'].items():
            if port in self.suspicious_ports and count > 10:
                risks.append({
                    'type': 'Suspicious Port Activity',
                    'description': f"High activity on {self.suspicious_ports[port]} port ({port}): {count} connections",
                    'severity': 'High',
                    'recommendation': f'Review access to {self.suspicious_ports[port]} service'
                })
        
        # External connections to private IPs
        for ip in self.analysis_results['ip_activity'].keys():
            if self._is_private_ip(ip) and self.analysis_results['ip_activity'][ip]['domains']:
                risks.append({
                    'type': 'Private IP External Access',
                    'description': f"Private IP {ip} making external connections",
                    'severity': 'Low',
                    'recommendation': 'Verify if external access from private IPs is intended'
                })
        
        self.analysis_results['security_issues'] = risks
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False
    
    def _is_public_ip(self, ip: str) -> bool:
        """Check if IP is public"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast)
        except ValueError:
            return False
    
    def _get_geolocation(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get geolocation for IP address"""
        if not self.geoip_reader:
            return None
        
        try:
            response = self.geoip_reader.city(ip)
            return {
                'country': response.country.name,
                'country_code': response.country.iso_code,
                'city': response.city.name,
                'latitude': float(response.location.latitude) if response.location.latitude else None,
                'longitude': float(response.location.longitude) if response.location.longitude else None
            }
        except geoip2.errors.AddressNotFoundError:
            return {'country': 'Unknown', 'city': 'Unknown'}
        except Exception:
            return None
    
    def _format_bytes(self, bytes_count: int) -> str:
        """Format bytes in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.1f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.1f} PB"
    
    def generate_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate comprehensive traffic analysis report"""
        duration_str = str(timedelta(seconds=int(analysis_results['duration'])))
        
        report_lines = [
            "NETWORK TRAFFIC ANALYSIS REPORT",
            "=" * 60,
            f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total Packets: {analysis_results['total_packets']:,}",
            f"Capture Duration: {duration_str}",
            "",
            "PROTOCOL BREAKDOWN:",
            "-" * 30
        ]
        
        # Protocol statistics
        total_protocol_packets = sum(analysis_results['protocols'].values())
        for protocol, count in sorted(analysis_results['protocols'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_protocol_packets * 100) if total_protocol_packets > 0 else 0
            report_lines.append(f"• {protocol}: {count:,} packets ({percentage:.1f}%)")
        
        # Top talkers
        report_lines.extend([
            "",
            "TOP TALKERS:",
            "-" * 20
        ])
        
        for i, talker in enumerate(analysis_results['top_talkers'][:10], 1):
            geo_info = ""
            if talker['geolocation'] and talker['geolocation'].get('country'):
                geo_info = f" [{talker['geolocation']['country']}]"
            
            report_lines.append(
                f"{i:2d}. {talker['ip']}{geo_info} - "
                f"{talker['total_packets']:,} packets, "
                f"{self._format_bytes(talker['total_bytes'])}, "
                f"{talker['domains_accessed']} domains"
            )
        
        # Port analysis
        report_lines.extend([
            "",
            "TOP PORTS:",
            "-" * 15
        ])
        
        sorted_ports = sorted(analysis_results['port_analysis'].items(), key=lambda x: x[1], reverse=True)
        for port, count in sorted_ports[:15]:
            service = self.common_ports.get(port, 'Unknown')
            report_lines.append(f"• Port {port} ({service}): {count:,} connections")
        
        # DNS queries
        if analysis_results['dns_queries']:
            report_lines.extend([
                "",
                "TOP DNS QUERIES:",
                "-" * 20
            ])
            
            sorted_dns = sorted(analysis_results['dns_queries'].items(), key=lambda x: x[1], reverse=True)
            for domain, count in sorted_dns[:15]:
                report_lines.append(f"• {domain}: {count} queries")
        
        # Anomalies
        if analysis_results['anomalies']:
            report_lines.extend([
                "",
                "ANOMALIES DETECTED:",
                "-" * 25
            ])
            
            for anomaly in analysis_results['anomalies']:
                report_lines.append(f"• [{anomaly['severity']}] {anomaly['type']}: {anomaly['description']}")
        
        # Security issues
        if analysis_results['security_issues']:
            report_lines.extend([
                "",
                "SECURITY RECOMMENDATIONS:",
                "-" * 30
            ])
            
            for issue in analysis_results['security_issues']:
                report_lines.extend([
                    f"• [{issue['severity']}] {issue['type']}",
                    f"  Description: {issue['description']}",
                    f"  Recommendation: {issue['recommendation']}",
                    ""
                ])
        
        report_lines.extend([
            "",
            "SUMMARY:",
            "-" * 10,
            f"• Total unique IPs: {len(analysis_results['ip_activity'])}",
            f"• Total protocols: {len(analysis_results['protocols'])}",
            f"• Total ports accessed: {len(analysis_results['port_analysis'])}",
            f"• Security issues found: {len(analysis_results['security_issues'])}",
            f"• Anomalies detected: {len(analysis_results['anomalies'])}",
            "",
            "Report generated by Network Traffic Analyzer"
        ])
        
        return "\n".join(report_lines)