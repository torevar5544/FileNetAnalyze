# File Analysis & Categorization System

## Overview

A comprehensive file analysis tool built with Streamlit that provides directory scanning, file categorization, and duplicate detection capabilities. The system analyzes file systems to categorize files by type, detect duplicates, and generate detailed reports with visualizations. It features specialized SMS file detection, configurable filtering options, and export functionality for analysis results.

## User Preferences

Preferred communication style: Simple, everyday language.

## Recent Changes

### January 2025 - Interface Enhancement
- Complete redesign with professional gradient styling and modern CSS
- Enhanced button designs with hover effects and smooth transitions
- Comprehensive export functionality (CSV, JSON, detailed reports)
- Advanced filtering and search capabilities
- Professional progress tracking with real-time status updates
- Created comprehensive README.md documentation

### January 2025 - Network Security Analysis Integration
- Added comprehensive PCAP analysis capabilities with Scapy integration
- Implemented network traffic analyzer with protocol categorization
- Built security-focused interface for anomaly detection and threat analysis
- Added IP activity breakdown with geolocation mapping
- Integrated port scanning detection and suspicious behavior alerts
- Created professional security reporting with actionable insights

## System Architecture

### Frontend Architecture
- **Streamlit Web Interface**: Single-page application with sidebar configuration panel
- **Interactive Visualizations**: Plotly-based charts and graphs for data presentation
- **Real-time Analysis**: Progress tracking and dynamic result updates during file scanning
- **Export Capabilities**: Built-in CSV and JSON export functionality for analysis results

### Backend Architecture
- **Modular Design**: Separation of concerns with dedicated analyzer, utilities, and main application modules
- **File Categorization Engine**: Rule-based classification system using file extensions and naming patterns
- **Duplicate Detection**: Hash-based file comparison for identifying duplicate content
- **Configurable SMS Detection**: Specialized logic for identifying SMS-related files with customizable parameters

### Data Processing
- **Path-based Analysis**: Uses Python's pathlib for cross-platform file system operations
- **Memory-efficient Scanning**: Iterative directory traversal to handle large file systems
- **Metadata Extraction**: File size, modification dates, and type classification
- **Statistical Aggregation**: File count summaries, size distributions, and category breakdowns

### Configuration System
- **Dynamic Parameter Adjustment**: Runtime configuration for file size filters, SMS detection rules, and scan options
- **Extension Mapping**: Predefined category mappings with support for custom SMS file types
- **Keyword-based Detection**: Flexible SMS file identification using filename pattern matching

## External Dependencies

### Core Libraries
- **Streamlit**: Web application framework for the user interface
- **Pandas**: Data manipulation and analysis for result processing
- **Plotly**: Interactive visualization library for charts and graphs
- **Pathlib**: File system path operations (built-in Python library)

### Utility Libraries
- **Collections**: Data structure utilities for counting and grouping (built-in)
- **Hashlib**: File content hashing for duplicate detection (built-in)
- **Mimetypes**: MIME type detection support (built-in)
- **DateTime**: Timestamp handling for file metadata (built-in)
- **JSON**: Data serialization for export functionality (built-in)
- **OS**: Operating system interface for file operations (built-in)

### File System Operations
- **Cross-platform Compatibility**: Built on Python's standard library for Windows, macOS, and Linux support
- **Permission Handling**: Error handling for restricted file access
- **Hidden File Detection**: Optional inclusion of system and hidden files in analysis