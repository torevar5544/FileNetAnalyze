# File Analysis & Categorization System

A comprehensive file analysis tool built with Streamlit that provides directory scanning, file categorization, and duplicate detection capabilities. The system analyzes file systems to categorize files by type, detect duplicates, and generate detailed reports with visualizations.

![File Analysis System](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-red.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## Features

### 🔍 **Comprehensive File Analysis**
- **Smart File Categorization**: Automatically categorizes files by type (Documents, Images, Videos, Audio, Code, etc.)
- **Duplicate Detection**: Identifies duplicate files based on name and size
- **SMS File Detection**: Specialized detection for SMS-related files with customizable parameters
- **File Metadata Extraction**: Collects file size, modification dates, and type information

### 📊 **Professional Interface**
- **Modern UI Design**: Gradient styling with smooth transitions and hover effects
- **Interactive Visualizations**: Plotly-based charts for data presentation
- **Real-time Progress Tracking**: Live updates during file scanning operations
- **Responsive Layout**: Clean, organized interface with collapsible sections

### 📈 **Advanced Reporting**
- **Multiple Export Formats**: CSV, JSON, and detailed text reports
- **Comprehensive Statistics**: File counts, size distributions, and category breakdowns
- **Filtering & Search**: Advanced filtering by category, size, and filename
- **Storage Efficiency Analysis**: Identifies wasted space from duplicate files

### ⚙️ **Configurable Options**
- **Flexible Scanning**: Include/exclude subdirectories and hidden files
- **Size Filtering**: Configurable minimum and maximum file size limits
- **Custom SMS Detection**: Adjustable file extensions and keyword patterns
- **Multiple Input Methods**: Directory path input or file upload

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Local Setup

1. **Clone or download the project files:**
   ```bash
   git clone <repository-url>
   cd file-analysis-system
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python -m venv file_analyzer_env
   
   # Activate the environment
   # Windows:
   file_analyzer_env\Scripts\activate
   # macOS/Linux:
   source file_analyzer_env/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install streamlit pandas plotly
   ```

4. **Create Streamlit configuration:**
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

5. **Run the application:**
   ```bash
   streamlit run app.py
   ```

The application will open in your browser at `http://localhost:8501`

### Alternative Installation with Requirements File

Create `requirements.txt`:
```
streamlit>=1.28.0
pandas>=2.0.0
plotly>=5.15.0
```

Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Getting Started

1. **Launch the application** using the installation instructions above
2. **Configure analysis options** in the sidebar:
   - Analysis scope (subdirectories, hidden files)
   - File size filters
   - SMS detection parameters
3. **Choose input method**:
   - Upload files directly, or
   - Enter a directory path for analysis
4. **Click "Analyze"** to start the file analysis process

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
file-analysis-system/
├── app.py                 # Main Streamlit application
├── file_analyzer.py       # Core analysis engine
├── utils.py              # Utility functions and helpers
├── .streamlit/
│   └── config.toml       # Streamlit configuration
├── requirements.txt      # Python dependencies
└── README.md            # This file
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

## Analysis Categories

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

## Features in Detail

### Duplicate Detection
- Identifies files with identical names and sizes
- Calculates wasted storage space
- Provides detailed duplicate file listings
- Shows potential storage savings

### Progress Tracking
- Real-time progress bars during analysis
- Status updates showing current file being processed
- Estimated completion times for large directories

### Interactive Visualizations
- Pie charts showing file type distribution
- Bar charts displaying storage usage by category
- Color-coded visualizations for easy interpretation

## Performance Considerations

- **Large Directories**: Analysis time scales with file count
- **Memory Usage**: Efficient processing for large file systems
- **Network Drives**: Local storage recommended for best performance
- **File Permissions**: Requires read access to analyzed directories

## Troubleshooting

### Common Issues

**Permission Denied:**
- Ensure read permissions for the target directory
- Run with appropriate user privileges
- Check if directory contains protected system files

**Port Already in Use:**
- Change port using `--server.port` flag
- Check for other running Streamlit applications
- Use `netstat` or `lsof` to identify port usage

**Large Directory Analysis:**
- Consider using file size filters for initial analysis
- Break large directories into smaller chunks
- Monitor system memory usage during analysis

### Error Messages

- **"Directory not found"**: Verify the path exists and is accessible
- **"Invalid directory path"**: Ensure the path points to a directory, not a file
- **"No files found"**: Check if directory contains files matching your filters

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