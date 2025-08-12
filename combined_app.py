import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
import json
import os
from datetime import datetime
import time

# Import analyzers
from file_analyzer import FileAnalyzer
from pcap_analyzer import NetworkTrafficAnalyzer, SCAPY_AVAILABLE
from utils import format_file_size, export_to_csv, export_to_json

# Configure page
st.set_page_config(
    page_title="Advanced Analysis System",
    page_icon="🔬",
    layout="wide"
)

# Combined CSS styling
st.markdown("""
<style>
    /* Main header styling */
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        color: white;
        text-align: center;
    }
    
    /* Security header styling */
    .security-header {
        background: linear-gradient(90deg, #dc2626 0%, #991b1b 100%);
        padding: 2rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        color: white;
        text-align: center;
    }
    
    /* Professional button styling */
    .stButton > button {
        background: linear-gradient(45deg, #667eea, #764ba2);
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
    
    /* Download button styling */
    .stDownloadButton > button {
        background: linear-gradient(45deg, #28a745, #20c997);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 0.6rem 1.2rem;
        font-weight: 600;
        transition: all 0.3s ease;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .stDownloadButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(0,0,0,0.15);
    }
    
    /* Metrics styling */
    .metric-container {
        background: white;
        padding: 1.5rem;
        border-radius: 10px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        border-left: 4px solid #667eea;
        margin: 0.5rem 0;
    }
    
    /* Network metrics */
    .network-metric {
        background: linear-gradient(135deg, #1e40af 0%, #1d4ed8 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 10px;
        text-align: center;
        margin: 0.5rem 0;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
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
    
    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        background-color: #f8f9fa;
        border-radius: 8px;
        border: 1px solid #e9ecef;
        padding: 0 1rem;
        font-weight: 600;
    }
    
    .stTabs [aria-selected="true"] {
        background: linear-gradient(45deg, #667eea, #764ba2);
        color: white;
    }
    
    /* Severity indicators */
    .severity-high { color: #dc2626; font-weight: bold; }
    .severity-medium { color: #d97706; font-weight: bold; }
    .severity-low { color: #059669; font-weight: bold; }
    
    /* IP address styling */
    .ip-address {
        font-family: monospace;
        background: #f3f4f6;
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
        border: 1px solid #d1d5db;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
def initialize_session_state():
    if 'analysis_results' not in st.session_state:
        st.session_state.analysis_results = None
    if 'pcap_results' not in st.session_state:
        st.session_state.pcap_results = None
    if 'analyzer' not in st.session_state:
        st.session_state.analyzer = FileAnalyzer()
    if 'network_analyzer' not in st.session_state:
        st.session_state.network_analyzer = NetworkTrafficAnalyzer() if SCAPY_AVAILABLE else None
    if 'analysis_mode' not in st.session_state:
        st.session_state.analysis_mode = "File Analysis"

def main():
    initialize_session_state()
    
    # Main navigation
    st.sidebar.markdown("## 🔬 Analysis System")
    analysis_mode = st.sidebar.radio(
        "Select Analysis Type:",
        ["File Analysis", "Network Security Analysis"],
        index=0 if st.session_state.analysis_mode == "File Analysis" else 1
    )
    
    st.session_state.analysis_mode = analysis_mode
    
    if analysis_mode == "File Analysis":
        run_file_analysis()
    else:
        run_network_analysis()

def run_file_analysis():
    """Run file analysis interface"""
    # File analysis header
    st.markdown("""
    <div class="main-header">
        <h1>📁 File Analysis & Categorization System</h1>
        <p>Comprehensive file analysis tool for directory scanning, categorization, and duplicate detection</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar for file analysis configuration
    with st.sidebar:
        st.markdown("### ⚙️ Configuration")
        
        # Analysis options
        with st.expander("📊 Analysis Options", expanded=True):
            include_subdirs = st.checkbox("Include subdirectories", value=True)
            detect_duplicates = st.checkbox("Detect duplicate files", value=True)
            include_hidden = st.checkbox("Include hidden files", value=False)
        
        # File size filters
        with st.expander("📏 File Size Filters"):
            min_size = st.number_input("Minimum file size (bytes)", min_value=0, value=0)
            max_size = st.number_input("Maximum file size (MB)", min_value=0, value=1000)
            max_size_bytes = max_size * 1024 * 1024 if max_size > 0 else float('inf')
        
        # SMS file detection
        with st.expander("📱 SMS File Detection"):
            sms_extensions = st.text_area(
                "SMS file extensions (comma-separated)",
                value="xml,csv,json,txt,db,sqlite",
                help="File extensions to consider as SMS-related files"
            )
            sms_keywords = st.text_area(
                "SMS filename keywords (comma-separated)",
                value="sms,message,text,conversation,chat",
                help="Keywords in filenames that indicate SMS-related files"
            )
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("### 📂 Directory Selection")
        
        # Directory input methods
        input_method = st.radio(
            "Choose input method:",
            ["Upload files", "Enter directory path"],
            help="Select how you want to provide files for analysis"
        )
        
        if input_method == "Upload files":
            uploaded_files = st.file_uploader(
                "Upload files for analysis",
                accept_multiple_files=True,
                help="Select multiple files to analyze their types and detect duplicates"
            )
            
            col_analyze, col_clear = st.columns(2)
            with col_analyze:
                if uploaded_files and st.button("🔍 Analyze Uploaded Files", type="primary"):
                    analyze_uploaded_files(uploaded_files, detect_duplicates, sms_extensions, sms_keywords)
            with col_clear:
                if st.button("🗑️ Clear Files"):
                    st.session_state.analysis_results = None
                    st.rerun()
        
        else:
            directory_path = st.text_input(
                "Enter directory path:",
                placeholder="/path/to/directory",
                help="Enter the full path to the directory you want to analyze"
            )
            
            col_analyze, col_clear = st.columns(2)
            with col_analyze:
                if directory_path and st.button("🔍 Analyze Directory", type="primary"):
                    if os.path.exists(directory_path) and os.path.isdir(directory_path):
                        analyze_directory(
                            directory_path, include_subdirs, detect_duplicates, 
                            include_hidden, min_size, max_size_bytes, 
                            sms_extensions, sms_keywords
                        )
                    else:
                        st.error("❌ Invalid directory path or directory does not exist")
            with col_clear:
                if st.button("🗑️ Clear Results"):
                    st.session_state.analysis_results = None
                    st.rerun()
    
    with col2:
        st.markdown("### 📊 Quick Stats")
        if st.session_state.analysis_results:
            results = st.session_state.analysis_results
            
            # Professional metrics display
            st.markdown(f"""
            <div class="metric-container">
                <h4>📁 Total Files</h4>
                <h2>{results['total_files']:,}</h2>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown(f"""
            <div class="metric-container">
                <h4>💾 Total Size</h4>
                <h2>{format_file_size(results['total_size'])}</h2>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown(f"""
            <div class="metric-container">
                <h4>📂 File Types</h4>
                <h2>{len(results['categories'])}</h2>
            </div>
            """, unsafe_allow_html=True)
            
            if results['duplicates']:
                st.markdown(f"""
                <div class="metric-container">
                    <h4>🔄 Duplicates</h4>
                    <h2>{len(results['duplicates'])}</h2>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("👋 Upload files or select a directory to begin analysis")
    
    # Display file analysis results
    if st.session_state.analysis_results:
        display_file_analysis_results()

def run_network_analysis():
    """Run network security analysis interface"""
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
        The required network analysis packages have been installed but may need system restart.
        """)
        return
    
    # Sidebar for network analysis configuration
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
        if st.button("📊 Generate Sample Network Analysis", type="secondary"):
            generate_sample_network_analysis()
    
    with col2:
        st.markdown("### 📊 Analysis Summary")
        if st.session_state.pcap_results:
            display_network_quick_stats(st.session_state.pcap_results)
        else:
            st.info("🔒 Upload a PCAP file to begin network security analysis")
    
    # Display network analysis results
    if st.session_state.pcap_results:
        display_network_analysis_results()

# File analysis functions (simplified versions)
def analyze_uploaded_files(uploaded_files, detect_duplicates, sms_extensions, sms_keywords):
    """Analyze uploaded files"""
    with st.spinner("🔄 Analyzing uploaded files..."):
        progress_container = st.container()
        with progress_container:
            progress_bar = st.progress(0)
            status_text = st.empty()
        
        # Configure analyzer
        st.session_state.analyzer.configure(
            sms_extensions=[ext.strip() for ext in sms_extensions.split(',') if ext.strip()],
            sms_keywords=[kw.strip() for kw in sms_keywords.split(',') if kw.strip()]
        )
        
        # Create temporary directory for uploaded files
        temp_dir = Path("temp_uploads")
        temp_dir.mkdir(exist_ok=True)
        
        try:
            # Save uploaded files temporarily
            file_paths = []
            for i, uploaded_file in enumerate(uploaded_files):
                progress = (i + 1) / len(uploaded_files)
                progress_bar.progress(progress)
                status_text.text(f"Processing {uploaded_file.name}... ({i+1}/{len(uploaded_files)})")
                
                temp_path = temp_dir / uploaded_file.name
                with open(temp_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                file_paths.append(temp_path)
            
            # Analyze files
            status_text.text("Analyzing file relationships and detecting duplicates...")
            results = st.session_state.analyzer.analyze_files(file_paths, detect_duplicates)
            st.session_state.analysis_results = results
            
            # Cleanup
            for file_path in file_paths:
                file_path.unlink(missing_ok=True)
            temp_dir.rmdir()
            
            progress_bar.progress(1.0)
            status_text.text("✅ Analysis complete!")
            time.sleep(1)
            progress_container.empty()
            
            st.success(f"✅ Successfully analyzed {len(uploaded_files)} files!")
            
        except Exception as e:
            st.error(f"❌ Error analyzing files: {str(e)}")

def analyze_directory(directory_path, include_subdirs, detect_duplicates, 
                     include_hidden, min_size, max_size_bytes, 
                     sms_extensions, sms_keywords):
    """Analyze directory"""
    with st.spinner("🔄 Scanning directory..."):
        progress_container = st.container()
        with progress_container:
            progress_bar = st.progress(0)
            status_text = st.empty()
        
        try:
            # Configure analyzer
            st.session_state.analyzer.configure(
                sms_extensions=[ext.strip() for ext in sms_extensions.split(',') if ext.strip()],
                sms_keywords=[kw.strip() for kw in sms_keywords.split(',') if kw.strip()]
            )
            
            # Analyze directory with progress callback
            def progress_callback(current, total, current_file):
                if total > 0:
                    progress = current / total
                    progress_bar.progress(progress)
                    status_text.text(f"Processing: {current_file} ({current}/{total})")
            
            results = st.session_state.analyzer.analyze_directory(
                directory_path, 
                recursive=include_subdirs,
                include_hidden=include_hidden,
                min_size=min_size,
                max_size=max_size_bytes,
                detect_duplicates=detect_duplicates,
                progress_callback=progress_callback
            )
            
            st.session_state.analysis_results = results
            
            progress_bar.progress(1.0)
            status_text.text("✅ Analysis complete!")
            time.sleep(1)
            progress_container.empty()
            
            st.success(f"✅ Successfully analyzed {results['total_files']} files!")
            
        except PermissionError:
            st.error("❌ Permission denied. Please check directory permissions.")
        except FileNotFoundError:
            st.error("❌ Directory not found.")
        except Exception as e:
            st.error(f"❌ Error during analysis: {str(e)}")

# Network analysis functions
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

def generate_sample_network_analysis():
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
            }
        },
        'anomalies': [
            {
                'type': 'Port Scanning',
                'description': 'IP 192.168.1.100 accessed 15 different ports on 10.0.0.1',
                'severity': 'High',
                'src_ip': '192.168.1.100'
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
            80: 500, 443: 1200, 53: 2000, 22: 50
        },
        'dns_queries': {
            'google.com': 150,
            'facebook.com': 120
        }
    }
    
    st.session_state.pcap_results = sample_results
    st.success("📊 Sample network analysis generated for demonstration!")

def display_network_quick_stats(results):
    """Display quick network statistics"""
    # Total packets
    st.markdown(f"""
    <div class="network-metric">
        <h4>📦 Total Packets</h4>
        <h2>{results['total_packets']:,}</h2>
    </div>
    """, unsafe_allow_html=True)
    
    # Duration
    duration_str = f"{results['duration']:.0f}s" if results['duration'] < 3600 else f"{results['duration']/3600:.1f}h"
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

# Display functions (simplified)
def display_file_analysis_results():
    """Display file analysis results"""
    st.markdown("### 📊 File Analysis Results")
    results = st.session_state.analysis_results
    
    tab1, tab2 = st.tabs(["📊 Overview", "📋 Export"])
    
    with tab1:
        if results.get('categories'):
            category_data = {
                'Category': list(results['categories'].keys()),
                'Count': [data['count'] for data in results['categories'].values()]
            }
            df_categories = pd.DataFrame(category_data)
            
            fig_pie = px.pie(
                df_categories,
                values='Count',
                names='Category',
                title="File Distribution by Category"
            )
            st.plotly_chart(fig_pie, use_container_width=True)
    
    with tab2:
        if st.button("📄 Export File Analysis Report"):
            report_text = f"""
FILE ANALYSIS REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Total Files: {results['total_files']:,}
Total Size: {format_file_size(results['total_size'])}
Categories: {len(results['categories'])}
Duplicates: {len(results.get('duplicates', []))}
            """
            
            st.download_button(
                label="⬇️ Download Report",
                data=report_text,
                file_name=f"file_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )

def display_network_analysis_results():
    """Display network analysis results"""
    st.markdown("### 🔒 Network Security Analysis Results")
    results = st.session_state.pcap_results
    
    tab1, tab2, tab3 = st.tabs(["🔍 Overview", "🚨 Security", "📋 Export"])
    
    with tab1:
        # Protocol distribution
        if results.get('protocols'):
            protocol_data = {
                'Protocol': list(results['protocols'].keys()),
                'Packets': list(results['protocols'].values())
            }
            df_protocols = pd.DataFrame(protocol_data)
            
            fig_pie = px.pie(
                df_protocols,
                values='Packets',
                names='Protocol',
                title="Network Protocol Distribution"
            )
            st.plotly_chart(fig_pie, use_container_width=True)
    
    with tab2:
        anomalies = results.get('anomalies', [])
        security_issues = results.get('security_issues', [])
        
        if anomalies:
            st.markdown("#### 🔍 Detected Anomalies")
            for anomaly in anomalies:
                severity_class = f"severity-{anomaly['severity'].lower()}"
                st.markdown(f"""
                <div class="anomaly-card">
                    <h5><span class="{severity_class}">[{anomaly['severity']}]</span> {anomaly['type']}</h5>
                    <p>{anomaly['description']}</p>
                </div>
                """, unsafe_allow_html=True)
        
        if security_issues:
            st.markdown("#### ⚠️ Security Recommendations")
            for issue in security_issues:
                severity_class = f"severity-{issue['severity'].lower()}"
                st.markdown(f"""
                <div class="anomaly-card">
                    <h5><span class="{severity_class}">[{issue['severity']}]</span> {issue['type']}</h5>
                    <p>{issue['description']}</p>
                    <p><strong>Recommendation:</strong> {issue['recommendation']}</p>
                </div>
                """, unsafe_allow_html=True)
        
        if not anomalies and not security_issues:
            st.success("✅ No security issues detected")
    
    with tab3:
        if st.button("📄 Export Network Security Report") and st.session_state.network_analyzer:
            report_text = st.session_state.network_analyzer.generate_report(results)
            
            st.download_button(
                label="⬇️ Download Security Report",
                data=report_text,
                file_name=f"network_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )

if __name__ == "__main__":
    main()