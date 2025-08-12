import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
import json
import os
from datetime import datetime
import time

from pcap_analyzer import NetworkTrafficAnalyzer, SCAPY_AVAILABLE
from utils import format_file_size, export_to_csv, export_to_json

# Configure page
st.set_page_config(
    page_title="Network Traffic Analysis System",
    page_icon="🔒",
    layout="wide"
)

# Custom CSS for professional security-focused styling
st.markdown("""
<style>
    /* Security-focused header styling */
    .security-header {
        background: linear-gradient(90deg, #dc2626 0%, #991b1b 100%);
        padding: 2rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        color: white;
        text-align: center;
    }
    
    /* Security alert styling */
    .security-alert {
        background: linear-gradient(45deg, #dc2626, #b91c1c);
        color: white;
        padding: 1rem;
        border-radius: 8px;
        margin: 0.5rem 0;
        border-left: 4px solid #fbbf24;
    }
    
    /* Anomaly card styling */
    .anomaly-card {
        background: #fef2f2;
        border: 1px solid #fecaca;
        border-left: 4px solid #dc2626;
        padding: 1rem;
        border-radius: 8px;
        margin: 0.5rem 0;
    }
    
    /* Network metric styling */
    .network-metric {
        background: linear-gradient(135deg, #1e40af 0%, #1d4ed8 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 10px;
        text-align: center;
        margin: 0.5rem 0;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    
    /* Protocol badge styling */
    .protocol-badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        background: #3b82f6;
        color: white;
        border-radius: 12px;
        font-size: 0.875rem;
        margin: 0.25rem;
    }
    
    /* IP address styling */
    .ip-address {
        font-family: monospace;
        background: #f3f4f6;
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
        border: 1px solid #d1d5db;
    }
    
    /* Severity indicators */
    .severity-high { color: #dc2626; font-weight: bold; }
    .severity-medium { color: #d97706; font-weight: bold; }
    .severity-low { color: #059669; font-weight: bold; }
    
    /* Custom button styling for security theme */
    .stButton > button {
        background: linear-gradient(45deg, #1e40af, #1d4ed8);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 0.6rem 1.2rem;
        font-weight: 600;
        transition: all 0.3s ease;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(0,0,0,0.15);
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'pcap_results' not in st.session_state:
    st.session_state.pcap_results = None
if 'network_analyzer' not in st.session_state:
    st.session_state.network_analyzer = NetworkTrafficAnalyzer() if SCAPY_AVAILABLE else None

def main():
    # Security-focused header
    st.markdown("""
    <div class="security-header">
        <h1>🔒 Network Traffic Analysis System</h1>
        <p>Advanced PCAP analysis for security professionals and network administrators</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Check if required dependencies are available
    if not SCAPY_AVAILABLE:
        st.error("""
        ⚠️ **Missing Dependencies**
        
        Scapy is required for PCAP analysis but is not installed.
        Please install it using: `pip install scapy`
        """)
        st.stop()
    
    # Sidebar for configuration
    with st.sidebar:
        st.markdown("### 🛡️ Analysis Configuration")
        
        # Analysis options
        with st.expander("🔍 Analysis Options", expanded=True):
            detect_anomalies = st.checkbox("Enable anomaly detection", value=True)
            geolocation_analysis = st.checkbox("Include geolocation analysis", value=True)
            deep_packet_inspection = st.checkbox("Deep packet inspection", value=True)
        
        # Security filters
        with st.expander("🚨 Security Filters"):
            min_packet_count = st.number_input("Minimum packet count for alerts", min_value=1, value=10)
            suspicious_threshold = st.number_input("Port scan threshold", min_value=5, value=10)
            high_volume_threshold = st.number_input("High volume threshold (packets)", min_value=100, value=1000)
        
        # Report options
        with st.expander("📊 Report Options"):
            include_ip_details = st.checkbox("Include detailed IP analysis", value=True)
            include_port_analysis = st.checkbox("Include port analysis", value=True)
            include_dns_analysis = st.checkbox("Include DNS analysis", value=True)
            include_geolocation = st.checkbox("Include geolocation mapping", value=True)
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("### 📁 PCAP File Analysis")
        
        # File upload
        uploaded_file = st.file_uploader(
            "Upload PCAP file for analysis",
            type=['pcap', 'pcapng', 'cap'],
            help="Select a PCAP file captured with Wireshark, tcpdump, or similar tools"
        )
        
        if uploaded_file:
            col_analyze, col_clear = st.columns(2)
            with col_analyze:
                if st.button("🔍 Analyze Network Traffic", type="primary"):
                    analyze_pcap_file(uploaded_file)
            with col_clear:
                if st.button("🗑️ Clear Analysis"):
                    st.session_state.pcap_results = None
                    st.rerun()
        
        # Sample data option for demo
        st.markdown("---")
        st.markdown("### 🧪 Demo Analysis")
        if st.button("📊 Generate Sample Analysis", type="secondary"):
            generate_sample_analysis()
    
    with col2:
        st.markdown("### 📊 Analysis Summary")
        if st.session_state.pcap_results:
            display_quick_stats(st.session_state.pcap_results)
        else:
            st.info("🔒 Upload a PCAP file to begin network security analysis")
    
    # Display results
    if st.session_state.pcap_results:
        display_network_analysis_results()

def analyze_pcap_file(uploaded_file):
    """Analyze uploaded PCAP file"""
    # Save uploaded file temporarily
    temp_dir = Path("temp_pcap")
    temp_dir.mkdir(exist_ok=True)
    temp_path = temp_dir / uploaded_file.name
    
    try:
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        with st.spinner("🔄 Analyzing network traffic..."):
            progress_container = st.container()
            with progress_container:
                progress_bar = st.progress(0)
                status_text = st.empty()
            
            def progress_callback(current, total, current_task):
                if total > 0:
                    progress = current / total
                    progress_bar.progress(progress)
                    status_text.text(f"{current_task} ({current}/{total})")
            
            # Analyze PCAP
            results = st.session_state.network_analyzer.analyze_pcap(
                str(temp_path), 
                progress_callback=progress_callback
            )
            
            st.session_state.pcap_results = results
            
            progress_bar.progress(1.0)
            status_text.text("✅ Network analysis complete!")
            time.sleep(1)
            progress_container.empty()
            
            st.success(f"✅ Successfully analyzed {results['total_packets']} packets!")
        
        # Cleanup
        temp_path.unlink(missing_ok=True)
        temp_dir.rmdir()
        
    except Exception as e:
        st.error(f"❌ Error analyzing PCAP file: {str(e)}")
        # Cleanup on error
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)
        if temp_dir.exists():
            temp_dir.rmdir()

def generate_sample_analysis():
    """Generate sample network analysis for demonstration"""
    sample_results = {
        'total_packets': 15420,
        'duration': 3600,  # 1 hour
        'protocols': {
            'TCP': 8500,
            'UDP': 4200,
            'DNS': 2000,
            'HTTP': 500,
            'HTTPS': 220
        },
        'ip_activity': {
            '192.168.1.100': {
                'packets_sent': 2500,
                'packets_received': 1800,
                'bytes_sent': 1024000,
                'bytes_received': 2048000,
                'domains': {'facebook.com', 'google.com', 'twitter.com'},
                'ports_accessed': {80, 443, 53, 8080},
                'geolocation': {'country': 'United States', 'city': 'San Francisco'}
            },
            '10.0.0.15': {
                'packets_sent': 1200,
                'packets_received': 900,
                'bytes_sent': 512000,
                'bytes_received': 768000,
                'domains': {'github.com', 'stackoverflow.com'},
                'ports_accessed': {443, 22, 3389},
                'geolocation': None
            }
        },
        'anomalies': [
            {
                'type': 'Port Scanning',
                'description': 'IP 192.168.1.100 accessed 15 different ports on 10.0.0.1',
                'severity': 'High',
                'src_ip': '192.168.1.100'
            },
            {
                'type': 'High Volume Traffic',
                'description': 'IP 10.0.0.15 generated 2100 packets (3.0 MB)',
                'severity': 'Medium',
                'ip': '10.0.0.15'
            }
        ],
        'security_issues': [
            {
                'type': 'Unencrypted HTTP Traffic',
                'description': 'Detected 500 HTTP packets',
                'severity': 'Medium',
                'recommendation': 'Consider migrating to HTTPS for better security'
            }
        ],
        'top_talkers': [
            {
                'ip': '192.168.1.100',
                'total_packets': 4300,
                'total_bytes': 3072000,
                'geolocation': {'country': 'United States', 'city': 'San Francisco'}
            }
        ],
        'port_analysis': {
            80: 500, 443: 1200, 53: 2000, 22: 50, 3389: 20, 8080: 100
        },
        'dns_queries': {
            'google.com': 150,
            'facebook.com': 120,
            'github.com': 80
        }
    }
    
    st.session_state.pcap_results = sample_results
    st.success("📊 Sample network analysis generated for demonstration!")

def display_quick_stats(results):
    """Display quick statistics in sidebar"""
    # Total packets
    st.markdown(f"""
    <div class="network-metric">
        <h4>📦 Total Packets</h4>
        <h2>{results['total_packets']:,}</h2>
    </div>
    """, unsafe_allow_html=True)
    
    # Duration
    duration_str = f"{results['duration']:.0f} seconds" if results['duration'] < 3600 else f"{results['duration']/3600:.1f} hours"
    st.markdown(f"""
    <div class="network-metric">
        <h4>⏱️ Duration</h4>
        <h2>{duration_str}</h2>
    </div>
    """, unsafe_allow_html=True)
    
    # Active IPs
    st.markdown(f"""
    <div class="network-metric">
        <h4>🌐 Active IPs</h4>
        <h2>{len(results.get('ip_activity', {}))}</h2>
    </div>
    """, unsafe_allow_html=True)
    
    # Security alerts
    alert_count = len(results.get('anomalies', [])) + len(results.get('security_issues', []))
    st.markdown(f"""
    <div class="network-metric">
        <h4>🚨 Security Alerts</h4>
        <h2>{alert_count}</h2>
    </div>
    """, unsafe_allow_html=True)

def display_network_analysis_results():
    """Display comprehensive network analysis results"""
    results = st.session_state.pcap_results
    
    # Security-focused tabs
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "🔍 Overview", "🚨 Security Alerts", "🌐 IP Analysis", "🔌 Port Analysis", "📊 Protocol Analysis", "📋 Full Report"
    ])
    
    with tab1:
        display_network_overview(results)
    
    with tab2:
        display_security_alerts(results)
    
    with tab3:
        display_ip_analysis(results)
    
    with tab4:
        display_port_analysis(results)
    
    with tab5:
        display_protocol_analysis(results)
    
    with tab6:
        display_full_network_report(results)

def display_network_overview(results):
    """Display network analysis overview"""
    st.markdown("### 🔍 Network Traffic Overview")
    
    # Key metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("📦 Total Packets", f"{results['total_packets']:,}")
    with col2:
        st.metric("🌐 Unique IPs", len(results.get('ip_activity', {})))
    with col3:
        st.metric("🔌 Ports Accessed", len(results.get('port_analysis', {})))
    with col4:
        alert_count = len(results.get('anomalies', [])) + len(results.get('security_issues', []))
        st.metric("🚨 Security Alerts", alert_count)
    
    # Protocol distribution
    if results.get('protocols'):
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 📊 Protocol Distribution")
            protocol_data = {
                'Protocol': list(results['protocols'].keys()),
                'Packets': list(results['protocols'].values())
            }
            df_protocols = pd.DataFrame(protocol_data)
            
            fig_pie = px.pie(
                df_protocols,
                values='Packets',
                names='Protocol',
                title="Network Protocols",
                color_discrete_sequence=px.colors.qualitative.Dark2
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        
        with col2:
            st.markdown("#### 📈 Traffic Volume by Protocol")
            fig_bar = px.bar(
                df_protocols,
                x='Protocol',
                y='Packets',
                title="Packet Count by Protocol",
                color='Packets',
                color_continuous_scale='Blues'
            )
            st.plotly_chart(fig_bar, use_container_width=True)

def display_security_alerts(results):
    """Display security alerts and anomalies"""
    st.markdown("### 🚨 Security Alerts & Anomalies")
    
    anomalies = results.get('anomalies', [])
    security_issues = results.get('security_issues', [])
    
    if not anomalies and not security_issues:
        st.success("✅ No security alerts detected in the network traffic")
        return
    
    # Anomalies
    if anomalies:
        st.markdown("#### 🔍 Detected Anomalies")
        for anomaly in anomalies:
            severity_class = f"severity-{anomaly['severity'].lower()}"
            st.markdown(f"""
            <div class="anomaly-card">
                <h5><span class="{severity_class}">[{anomaly['severity']}]</span> {anomaly['type']}</h5>
                <p>{anomaly['description']}</p>
                {f"<p><strong>Source IP:</strong> <span class='ip-address'>{anomaly.get('src_ip', 'Unknown')}</span></p>" if anomaly.get('src_ip') else ""}
            </div>
            """, unsafe_allow_html=True)
    
    # Security issues
    if security_issues:
        st.markdown("#### ⚠️ Security Recommendations")
        for issue in security_issues:
            severity_class = f"severity-{issue['severity'].lower()}"
            st.markdown(f"""
            <div class="anomaly-card">
                <h5><span class="{severity_class}">[{issue['severity']}]</span> {issue['type']}</h5>
                <p><strong>Description:</strong> {issue['description']}</p>
                <p><strong>Recommendation:</strong> {issue['recommendation']}</p>
            </div>
            """, unsafe_allow_html=True)
    
    # Export alerts
    if anomalies or security_issues:
        st.markdown("#### 💾 Export Security Data")
        if st.button("📄 Export Security Report", type="secondary"):
            report_data = generate_security_report(results)
            st.download_button(
                label="⬇️ Download Security Report",
                data=report_data,
                file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )

def display_ip_analysis(results):
    """Display detailed IP analysis"""
    st.markdown("### 🌐 IP Address Analysis")
    
    ip_activity = results.get('ip_activity', {})
    if not ip_activity:
        st.info("No IP activity data available")
        return
    
    # Top talkers table
    if results.get('top_talkers'):
        st.markdown("#### 📊 Top Network Talkers")
        
        talker_rows = []
        for talker in results['top_talkers'][:15]:
            geo_info = "Unknown"
            if talker.get('geolocation') and talker['geolocation'].get('country'):
                geo_info = f"{talker['geolocation']['country']}"
                if talker['geolocation'].get('city'):
                    geo_info += f", {talker['geolocation']['city']}"
            
            talker_rows.append({
                'IP Address': talker['ip'],
                'Total Packets': f"{talker['total_packets']:,}",
                'Total Bytes': format_file_size(talker['total_bytes']),
                'Packets Sent': f"{talker.get('packets_sent', 0):,}",
                'Packets Received': f"{talker.get('packets_received', 0):,}",
                'Location': geo_info
            })
        
        df_talkers = pd.DataFrame(talker_rows)
        st.dataframe(df_talkers, use_container_width=True, height=400)
    
    # Detailed IP activity
    st.markdown("#### 🔍 Detailed IP Activity")
    
    # Create expandable sections for each IP
    for ip, activity in list(ip_activity.items())[:10]:  # Show top 10 IPs
        total_packets = activity['packets_sent'] + activity['packets_received']
        total_bytes = activity['bytes_sent'] + activity['bytes_received']
        
        with st.expander(f"🌐 {ip} - {total_packets:,} packets, {format_file_size(total_bytes)}"):
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.markdown("**Traffic Statistics:**")
                st.write(f"Packets Sent: {activity['packets_sent']:,}")
                st.write(f"Packets Received: {activity['packets_received']:,}")
                st.write(f"Bytes Sent: {format_file_size(activity['bytes_sent'])}")
                st.write(f"Bytes Received: {format_file_size(activity['bytes_received'])}")
            
            with col2:
                st.markdown("**Network Activity:**")
                domains = list(activity.get('domains', set()))[:5]
                st.write(f"Domains Accessed: {len(activity.get('domains', set()))}")
                if domains:
                    for domain in domains:
                        st.write(f"  • {domain}")
                
                ports = list(activity.get('ports_accessed', set()))[:10]
                st.write(f"Ports Accessed: {len(activity.get('ports_accessed', set()))}")
                if ports:
                    st.write(f"  • {', '.join(map(str, sorted(ports)))}")
            
            with col3:
                st.markdown("**Geolocation:**")
                geo = activity.get('geolocation')
                if geo and geo.get('country'):
                    st.write(f"Country: {geo['country']}")
                    if geo.get('city'):
                        st.write(f"City: {geo['city']}")
                else:
                    st.write("Location: Unknown/Private IP")

def display_port_analysis(results):
    """Display port analysis"""
    st.markdown("### 🔌 Port Analysis")
    
    port_analysis = results.get('port_analysis', {})
    if not port_analysis:
        st.info("No port analysis data available")
        return
    
    # Port activity chart
    sorted_ports = sorted(port_analysis.items(), key=lambda x: x[1], reverse=True)[:20]
    port_data = {
        'Port': [f"{port}" for port, count in sorted_ports],
        'Connections': [count for port, count in sorted_ports],
        'Service': [st.session_state.network_analyzer.common_ports.get(port, 'Unknown') for port, count in sorted_ports]
    }
    
    df_ports = pd.DataFrame(port_data)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 📊 Most Active Ports")
        fig_bar = px.bar(
            df_ports.head(15),
            x='Port',
            y='Connections',
            hover_data=['Service'],
            title="Connection Count by Port",
            color='Connections',
            color_continuous_scale='Reds'
        )
        fig_bar.update_xaxis(title='Port Number')
        st.plotly_chart(fig_bar, use_container_width=True)
    
    with col2:
        st.markdown("#### 🛡️ Security-Relevant Ports")
        suspicious_ports_data = []
        
        for port, count in sorted_ports:
            if port in st.session_state.network_analyzer.suspicious_ports:
                suspicious_ports_data.append({
                    'Port': port,
                    'Service': st.session_state.network_analyzer.suspicious_ports[port],
                    'Connections': count,
                    'Risk Level': 'High' if count > 10 else 'Medium'
                })
        
        if suspicious_ports_data:
            df_suspicious = pd.DataFrame(suspicious_ports_data)
            st.dataframe(df_suspicious, use_container_width=True)
        else:
            st.success("✅ No suspicious port activity detected")
    
    # Detailed port table
    st.markdown("#### 📋 Complete Port Activity")
    st.dataframe(df_ports, use_container_width=True, height=400)

def display_protocol_analysis(results):
    """Display protocol analysis"""
    st.markdown("### 📊 Protocol Analysis")
    
    protocols = results.get('protocols', {})
    if not protocols:
        st.info("No protocol data available")
        return
    
    # Protocol breakdown
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🔍 Protocol Distribution")
        protocol_data = []
        total_packets = sum(protocols.values())
        
        for protocol, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            protocol_data.append({
                'Protocol': protocol,
                'Packet Count': f"{count:,}",
                'Percentage': f"{percentage:.1f}%",
                'Raw Count': count
            })
        
        df_protocols = pd.DataFrame(protocol_data)
        st.dataframe(df_protocols[['Protocol', 'Packet Count', 'Percentage']], use_container_width=True)
    
    with col2:
        st.markdown("#### 📈 Protocol Timeline")
        # Create a simple visualization
        fig_pie = px.pie(
            df_protocols,
            values='Raw Count',
            names='Protocol',
            title="Protocol Distribution"
        )
        st.plotly_chart(fig_pie, use_container_width=True)
    
    # DNS analysis if available
    dns_queries = results.get('dns_queries', {})
    if dns_queries:
        st.markdown("#### 🔍 DNS Query Analysis")
        sorted_dns = sorted(dns_queries.items(), key=lambda x: x[1], reverse=True)[:20]
        
        dns_data = {
            'Domain': [domain for domain, count in sorted_dns],
            'Query Count': [count for domain, count in sorted_dns]
        }
        
        df_dns = pd.DataFrame(dns_data)
        
        col1, col2 = st.columns(2)
        with col1:
            st.dataframe(df_dns, use_container_width=True)
        
        with col2:
            fig_bar = px.bar(
                df_dns.head(10),
                x='Query Count',
                y='Domain',
                orientation='h',
                title="Top DNS Queries"
            )
            st.plotly_chart(fig_bar, use_container_width=True)

def display_full_network_report(results):
    """Display full network analysis report"""
    st.markdown("### 📋 Complete Network Analysis Report")
    
    if not st.session_state.network_analyzer:
        st.error("Network analyzer not available")
        return
    
    # Generate comprehensive report
    report_text = st.session_state.network_analyzer.generate_report(results)
    
    # Display report in expandable text area
    with st.expander("📄 View Full Text Report", expanded=True):
        st.text_area("Network Analysis Report", report_text, height=600)
    
    # Export options
    st.markdown("#### 💾 Export Complete Analysis")
    
    export_col1, export_col2, export_col3 = st.columns(3)
    
    with export_col1:
        if st.button("📄 Export Text Report", type="secondary"):
            st.download_button(
                label="⬇️ Download Text Report",
                data=report_text,
                file_name=f"network_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )
    
    with export_col2:
        if st.button("📊 Export Raw Data", type="secondary"):
            json_data = json.dumps(results, indent=2, default=str)
            st.download_button(
                label="⬇️ Download JSON Data",
                data=json_data,
                file_name=f"network_analysis_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
    
    with export_col3:
        if st.button("🔒 Export Security Summary", type="secondary"):
            security_summary = generate_security_summary(results)
            st.download_button(
                label="⬇️ Download Security Summary",
                data=security_summary,
                file_name=f"security_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )

def generate_security_report(results):
    """Generate focused security report"""
    anomalies = results.get('anomalies', [])
    security_issues = results.get('security_issues', [])
    
    report_lines = [
        "NETWORK SECURITY ANALYSIS REPORT",
        "=" * 50,
        f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total Packets Analyzed: {results.get('total_packets', 0):,}",
        "",
        "SECURITY SUMMARY:",
        f"• Anomalies Detected: {len(anomalies)}",
        f"• Security Issues: {len(security_issues)}",
        f"• Active IP Addresses: {len(results.get('ip_activity', {}))}",
        ""
    ]
    
    if anomalies:
        report_lines.extend([
            "DETECTED ANOMALIES:",
            "-" * 25
        ])
        for anomaly in anomalies:
            report_lines.extend([
                f"[{anomaly['severity']}] {anomaly['type']}",
                f"Description: {anomaly['description']}",
                ""
            ])
    
    if security_issues:
        report_lines.extend([
            "SECURITY RECOMMENDATIONS:",
            "-" * 30
        ])
        for issue in security_issues:
            report_lines.extend([
                f"[{issue['severity']}] {issue['type']}",
                f"Description: {issue['description']}",
                f"Recommendation: {issue['recommendation']}",
                ""
            ])
    
    return "\n".join(report_lines)

def generate_security_summary(results):
    """Generate executive security summary"""
    total_packets = results.get('total_packets', 0)
    anomaly_count = len(results.get('anomalies', []))
    security_issue_count = len(results.get('security_issues', []))
    ip_count = len(results.get('ip_activity', {}))
    
    summary_lines = [
        "EXECUTIVE SECURITY SUMMARY",
        "=" * 35,
        f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "KEY FINDINGS:",
        f"• Network traffic volume: {total_packets:,} packets analyzed",
        f"• Active network endpoints: {ip_count} IP addresses",
        f"• Security alerts generated: {anomaly_count + security_issue_count}",
        f"• Risk level: {'HIGH' if anomaly_count > 5 else 'MEDIUM' if anomaly_count > 0 else 'LOW'}",
        "",
        "RECOMMENDATIONS:",
        "• Review all high-severity security alerts",
        "• Investigate suspicious port scanning activity",
        "• Consider implementing additional monitoring",
        "• Update security policies based on findings",
        "",
        "This analysis was generated by the Network Traffic Analysis System"
    ]
    
    return "\n".join(summary_lines)

if __name__ == "__main__":
    main()