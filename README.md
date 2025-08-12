# Advanced Analysis System: File & Network Security Analysis

A comprehensive analysis platform built with Streamlit that provides both file system analysis and network security analysis capabilities. The system combines file categorization, duplicate detection, and PCAP network traffic analysis with professional security reporting and threat detection.

![Analysis System](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-red.svg)
![Network Security](https://img.shields.io/badge/Security-PCAP_Analysis-red.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## Features

### 📁 **Comprehensive File Analysis**
- **Smart File Categorization**: Automatically categorizes files by type (Documents, Images, Videos, Audio, Code, etc.)
- **Duplicate Detection**: Identifies duplicate files based on name and size
- **SMS File Detection**: Specialized detection for SMS-related files with customizable parameters
- **File Metadata Extraction**: Collects file size, modification dates, and type information
- **Storage Efficiency Analysis**: Identifies wasted space from duplicate files

### 🔒 **Advanced Network Security Analysis**
- **PCAP File Analysis**: Complete packet capture analysis using Scapy
- **Protocol Categorization**: Classify traffic by HTTP, HTTPS, DNS, TCP, UDP, and more
- **IP Activity Breakdown**: Detailed analysis of source/destination IP behavior
- **Anomaly Detection**: Automated detection of port scanning, suspicious connections, and unusual traffic patterns
- **Geolocation Mapping**: Correlate IP addresses with geographic locations (when GeoIP database available)
- **Security Threat Assessment**: Identify policy violations, unencrypted traffic, and potential security risks

### 🛡️ **Professional Security Interface**
- **Security-Focused Design**: Red gradient styling for security analysis mode
- **Real-time Threat Alerts**: Live security alerts with severity classifications (High/Medium/Low)
- **Interactive Network Visualizations**: Protocol distribution charts, traffic analysis, and port activity graphs
- **Comprehensive Security Reports**: Actionable insights for network administrators and security teams

### 📊 **Advanced Reporting & Export**
- **Multiple Export Formats**: CSV, JSON, and detailed security reports
- **Executive Summaries**: High-level security summaries for management
- **Detailed Technical Reports**: In-depth analysis for security professionals
- **Filtering & Search**: Advanced filtering by IP, protocol, severity, and time ranges
- **Custom Report Generation**: Tailored reports for specific security requirements

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Administrative privileges (for network analysis features)

### Local Setup

1. **Clone or download the project files:**
   ```bash
   git clone <repository-url>
   cd advanced-analysis-system
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python -m venv analysis_env
   
   # Activate the environment
   # Windows:
   analysis_env\Scripts\activate
   # macOS/Linux:
   source analysis_env/bin/activate
   ```

3. **Install core dependencies:**
   ```bash
   pip install streamlit pandas plotly pathlib
   ```

4. **Install network analysis dependencies:**
   ```bash
   pip install scapy geoip2 maxminddb requests ipaddress
   ```
   
   **Note for Windows users:** Scapy may require WinPcap or Npcap:
   - Download and install [Npcap](https://nmap.org/npcap/) for Windows
   - Restart your command prompt after installation

5. **Optional: Install GeoIP database for location mapping:**
   ```bash
   # Download GeoLite2 City database from MaxMind (free registration required)
   # Place GeoLite2-City.mmdb in the project root directory
   ```

6. **Create Streamlit configuration:**
   ```bash
   mkdir .streamlit
   ```
   
   Create `.streamlit/config.toml`:
   ```toml
   [server]
   headless = true
   address = "0.0.0.0"
   port = 8501
   ```

7. **Run the application:**
   ```bash
   # For combined file and network analysis
   streamlit run combined_app.py
   
   # Or run individual components
   streamlit run app.py              # File analysis only
   streamlit run network_app.py      # Network analysis only
   ```

The application will open in your browser at `http://localhost:8501`

### Complete Requirements File

Create `requirements.txt`:
```
streamlit>=1.28.0
pandas>=2.0.0
plotly>=5.15.0
scapy>=2.6.0
geoip2>=5.1.0
maxminddb>=2.8.0
requests>=2.31.0
ipaddress>=1.0.23
```

Install all dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Getting Started

1. **Launch the application** using the installation instructions above
2. **Select analysis mode** from the sidebar:
   - **File Analysis**: For directory scanning and file categorization
   - **Network Security Analysis**: For PCAP file analysis and security assessment

### File Analysis Mode

1. **Configure analysis options** in the sidebar:
   - Analysis scope (subdirectories, hidden files)
   - File size filters
   - SMS detection parameters
2. **Choose input method**:
   - Upload files directly, or
   - Enter a directory path for analysis
3. **Click "Analyze"** to start the file analysis process

### Network Security Analysis Mode

1. **Configure security analysis options** in the sidebar:
   - Enable anomaly detection
   - Set security thresholds
   - Configure geolocation analysis
2. **Upload PCAP file**:
   - Support for .pcap, .pcapng, and .cap files
   - Files captured with Wireshark, tcpdump, or similar tools
3. **Review security analysis**:
   - Protocol distribution and traffic patterns
   - Security alerts and anomalies
   - IP activity and geolocation data
   - Port analysis and suspicious behavior detection

### Analysis Options

#### File Size Filters
- **Minimum Size**: Set minimum file size in bytes
- **Maximum Size**: Set maximum file size in MB
- **Hidden Files**: Choose whether to include system/hidden files

#### SMS File Detection
- **Extensions**: Customize file extensions to consider as SMS files
- **Keywords**: Define filename keywords that indicate SMS-related content

### Export Options

The system provides multiple export formats:

- **CSV Export**: Spreadsheet-compatible format for data analysis
- **JSON Export**: Structured data format for programmatic use
- **Text Reports**: Human-readable summaries with statistics
- **Filtered Results**: Export only filtered/searched results

## File Structure

```
advanced-analysis-system/
├── combined_app.py        # Main combined analysis application
├── app.py                 # File analysis application
├── network_app.py         # Network security analysis application
├── file_analyzer.py       # File analysis engine
├── pcap_analyzer.py       # Network traffic analysis engine
├── utils.py              # Utility functions and helpers
├── .streamlit/
│   └── config.toml       # Streamlit configuration
├── requirements.txt      # Python dependencies
├── README.md            # This documentation
└── replit.md           # Project architecture documentation
```

## Configuration

### Port Configuration

To change the default port:

**Command line:**
```bash
streamlit run app.py --server.port 8080
```

**Configuration file (.streamlit/config.toml):**
```toml
[server]
port = 8080
address = "localhost"
```

**Environment variable:**
```bash
export STREAMLIT_SERVER_PORT=8080
streamlit run app.py
```

### SMS Detection Customization

Customize SMS file detection in the sidebar:
- **Extensions**: Common SMS formats (xml, csv, json, txt, db, sqlite)
- **Keywords**: Filename patterns (sms, message, text, conversation, chat)

### Network Security Configuration

Configure network analysis parameters:
- **Anomaly Detection**: Enable/disable automatic threat detection
- **Security Thresholds**: Set packet count thresholds for alerts
- **Port Scan Detection**: Configure sensitivity for port scanning detection
- **Geolocation Analysis**: Enable IP geolocation mapping (requires GeoIP database)

## Analysis Categories

### File Categories

The system automatically categorizes files into:

- **Documents**: PDF, DOC, DOCX, TXT, RTF, ODT, Pages
- **Images**: JPG, PNG, GIF, BMP, SVG, WebP, TIFF, ICO
- **Videos**: MP4, AVI, MKV, MOV, WMV, FLV, WebM, M4V
- **Audio**: MP3, WAV, FLAC, AAC, OGG, WMA, M4A
- **Archives**: ZIP, RAR, 7Z, TAR, GZ, BZ2, XZ
- **Spreadsheets**: XLS, XLSX, CSV, ODS
- **Presentations**: PPT, PPTX, ODP, KEY
- **Code**: PY, JS, HTML, CSS, Java, CPP, C, PHP, RB, GO, RS
- **Executables**: EXE, MSI, DEB, RPM, DMG, APP
- **Fonts**: TTF, OTF, WOFF, WOFF2, EOT
- **Data**: JSON, XML, YAML, YML, SQL, DB, SQLite
- **Other**: Files not matching the above categories

### Network Protocol Analysis

The system analyzes and categorizes network protocols:

- **Application Layer**: HTTP, HTTPS, DNS, FTP, SMTP, POP3, IMAP
- **Transport Layer**: TCP, UDP with port analysis
- **Network Layer**: IP traffic analysis with source/destination mapping
- **Security Protocols**: SSH, TLS/SSL, VPN traffic identification
- **Suspicious Activity**: Port scanning, unusual connections, high-volume traffic

## Features in Detail

### File Analysis Features

#### Duplicate Detection
- Identifies files with identical names and sizes
- Calculates wasted storage space
- Provides detailed duplicate file listings
- Shows potential storage savings

#### Progress Tracking
- Real-time progress bars during analysis
- Status updates showing current file being processed
- Estimated completion times for large directories

#### Interactive Visualizations
- Pie charts showing file type distribution
- Bar charts displaying storage usage by category
- Color-coded visualizations for easy interpretation

### Network Security Features

#### Traffic Analysis
- **Protocol Breakdown**: Detailed analysis of network protocols (TCP, UDP, HTTP, DNS, etc.)
- **IP Activity Mapping**: Complete source/destination IP analysis with traffic volumes
- **Session Tracking**: Monitor connection attempts, duration, and data transfer
- **Port Analysis**: Identify open ports, services, and potential vulnerabilities

#### Security Threat Detection
- **Anomaly Detection**: Automated detection of unusual network behavior
- **Port Scanning Alerts**: Identify potential reconnaissance activities
- **High Volume Traffic**: Flag excessive data transfers or connection attempts
- **Suspicious Protocol Usage**: Detect potentially malicious network activity

#### Geolocation Intelligence
- **IP Geolocation**: Map IP addresses to geographic locations
- **Country-based Analysis**: Identify traffic origins and destinations
- **Network Topology Insights**: Understand network communication patterns

#### Security Reporting
- **Executive Summaries**: High-level security assessment for management
- **Technical Reports**: Detailed findings for security professionals
- **Actionable Recommendations**: Specific steps to improve network security
- **Compliance Documentation**: Reports suitable for security audits

## Performance Considerations

### File Analysis Performance
- **Large Directories**: Analysis time scales with file count
- **Memory Usage**: Efficient processing for large file systems
- **Network Drives**: Local storage recommended for best performance
- **File Permissions**: Requires read access to analyzed directories

### Network Analysis Performance
- **PCAP File Size**: Large packet captures may require significant processing time
- **Memory Requirements**: Network analysis can be memory-intensive for large captures
- **Processing Power**: Complex packet analysis benefits from faster CPUs
- **Network Permissions**: Some network analysis features may require administrative privileges

## Troubleshooting

### Common Issues

#### General Issues

**Permission Denied:**
- Ensure read permissions for the target directory/files
- Run with appropriate user privileges
- Check if directory contains protected system files

**Port Already in Use:**
- Change port using `--server.port` flag
- Check for other running Streamlit applications
- Use `netstat` or `lsof` to identify port usage

#### File Analysis Issues

**Large Directory Analysis:**
- Consider using file size filters for initial analysis
- Break large directories into smaller chunks
- Monitor system memory usage during analysis

**Error Messages:**
- **"Directory not found"**: Verify the path exists and is accessible
- **"Invalid directory path"**: Ensure the path points to a directory, not a file
- **"No files found"**: Check if directory contains files matching your filters

#### Network Analysis Issues

**Scapy Installation Problems:**
- **Windows**: Install Npcap from https://nmap.org/npcap/
- **Linux**: May require `sudo apt-get install python3-scapy`
- **macOS**: Use `brew install scapy` or pip installation

**PCAP File Issues:**
- **"Cannot read PCAP file"**: Verify file is not corrupted and is a valid packet capture
- **"Permission denied"**: Ensure read access to PCAP files
- **"Unsupported format"**: Check file extension (.pcap, .pcapng, .cap supported)

**GeoIP Database Issues:**
- **Missing location data**: Download GeoLite2-City.mmdb from MaxMind
- **"Database not found"**: Place GeoIP database in project root directory
- **Outdated location data**: Update GeoIP database regularly for accuracy

**Network Analysis Performance:**
- **Slow analysis**: Large PCAP files require significant processing time
- **Memory issues**: Close other applications when analyzing large packet captures
- **Incomplete analysis**: Ensure sufficient disk space for temporary processing files

## Contributing

Contributions are welcome! Areas for improvement:
- Additional file type categories
- Performance optimizations
- New export formats
- Enhanced visualizations
- Additional analysis metrics

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Technical Architecture

### Backend Components
- **FileAnalyzer**: Core analysis engine with configurable parameters
- **Utils**: Helper functions for formatting, export, and calculations
- **Path Operations**: Cross-platform file system handling

### Frontend Components
- **Streamlit Interface**: Modern web-based UI with professional styling
- **Plotly Visualizations**: Interactive charts and graphs
- **CSS Styling**: Custom themes with gradient designs and animations

### Data Processing
- **Memory Efficient**: Iterative processing for large file systems
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **Error Handling**: Robust handling of permission and access issues

## Support

For issues, questions, or feature requests:
1. Check the troubleshooting section above
2. Review the configuration options
3. Verify system requirements and dependencies

---

**Built with ❤️ using Streamlit, Pandas, and Plotly**