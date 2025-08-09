import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
import json
import os
from datetime import datetime
import time

from file_analyzer import FileAnalyzer
from utils import format_file_size, export_to_csv, export_to_json

# Configure page
st.set_page_config(
    page_title="File Analysis & Categorization System",
    page_icon="📁",
    layout="wide"
)

# Custom CSS for professional styling
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
    
    /* Sidebar styling */
    .sidebar-section {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 1rem;
        border: 1px solid #e9ecef;
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
    
    /* Alert styling */
    .stAlert {
        border-radius: 8px;
    }
    
    /* Progress bar styling */
    .stProgress .st-bo {
        background-color: #667eea;
    }
    
    /* Export section styling */
    .export-section {
        background: #f8f9fa;
        padding: 1.5rem;
        border-radius: 10px;
        border: 1px solid #e9ecef;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = None
if 'analyzer' not in st.session_state:
    st.session_state.analyzer = FileAnalyzer()

def main():
    # Main header with professional styling
    st.markdown("""
    <div class="main-header">
        <h1>📁 File Analysis & Categorization System</h1>
        <p>Comprehensive file analysis tool for directory scanning, categorization, and duplicate detection</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar for configuration
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
    
    # Display results
    if st.session_state.analysis_results:
        display_analysis_results()

def analyze_uploaded_files(uploaded_files, detect_duplicates, sms_extensions, sms_keywords):
    """Analyze uploaded files with professional progress tracking"""
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
    """Analyze directory with professional progress tracking"""
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

def display_analysis_results():
    """Display comprehensive analysis results with professional styling"""
    results = st.session_state.analysis_results
    
    # Professional tabs with better styling
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📊 Overview", "📁 Categories", "🔍 Duplicates", "📱 SMS Files", "📋 Detailed Report"
    ])
    
    with tab1:
        display_overview(results)
    
    with tab2:
        display_categories(results)
    
    with tab3:
        display_duplicates(results)
    
    with tab4:
        display_sms_files(results)
    
    with tab5:
        display_detailed_report(results)

def display_overview(results):
    """Display professional overview charts and statistics"""
    st.markdown("### 📊 Analysis Overview")
    
    # Enhanced summary metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("📁 Total Files", f"{results['total_files']:,}", delta=None)
    with col2:
        st.metric("💾 Total Size", format_file_size(results['total_size']), delta=None)
    with col3:
        st.metric("📂 File Categories", len(results['categories']), delta=None)
    with col4:
        duplicate_count = len(results['duplicates']) if results['duplicates'] else 0
        st.metric("🔄 Duplicates", duplicate_count, delta=None)
    
    if results['categories']:
        # Professional chart styling
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 📊 File Type Distribution")
            category_data = {
                'Category': [cat for cat in results['categories'].keys()],
                'Count': [data['count'] for data in results['categories'].values()]
            }
            df_categories = pd.DataFrame(category_data)
            
            fig_pie = px.pie(
                df_categories, 
                values='Count', 
                names='Category',
                title="Files by Category",
                color_discrete_sequence=px.colors.qualitative.Set3
            )
            fig_pie.update_traces(textposition='inside', textinfo='percent+label')
            fig_pie.update_layout(
                font=dict(size=12),
                showlegend=True,
                legend=dict(orientation="v", yanchor="middle", y=0.5, xanchor="left", x=1.01)
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        
        with col2:
            st.markdown("#### 💾 Storage Distribution")
            size_data = {
                'Category': [cat for cat in results['categories'].keys()],
                'Size': [data['total_size'] for data in results['categories'].values()]
            }
            df_sizes = pd.DataFrame(size_data)
            
            fig_bar = px.bar(
                df_sizes,
                x='Category',
                y='Size',
                title="Storage by Category",
                color='Size',
                color_continuous_scale='Blues'
            )
            fig_bar.update_layout(
                xaxis_tickangle=-45,
                font=dict(size=12),
                yaxis_title="Size (bytes)"
            )
            st.plotly_chart(fig_bar, use_container_width=True)

def display_categories(results):
    """Display detailed category information with professional export options"""
    st.markdown("### 📁 File Categories")
    
    if not results['categories']:
        st.info("ℹ️ No files found in the analysis.")
        return
    
    # Create professional category table
    category_rows = []
    for category, data in results['categories'].items():
        category_rows.append({
            'Category': category,
            'File Count': data['count'],
            'Total Size': format_file_size(data['total_size']),
            'Average Size': format_file_size(data['total_size'] / data['count'] if data['count'] > 0 else 0),
            'Extensions': ', '.join(data['extensions'][:5]) + ('...' if len(data['extensions']) > 5 else '')
        })
    
    df_categories = pd.DataFrame(category_rows)
    st.dataframe(df_categories, use_container_width=True, height=400)
    
    # Professional export section
    st.markdown("#### 💾 Export Category Data")
    export_col1, export_col2, export_col3 = st.columns(3)
    
    with export_col1:
        if st.button("📄 Export as CSV", type="secondary"):
            csv_data = export_to_csv(df_categories)
            st.download_button(
                label="⬇️ Download CSV",
                data=csv_data,
                file_name=f"file_categories_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    
    with export_col2:
        if st.button("📋 Export as JSON", type="secondary"):
            json_data = export_to_json(results['categories'])
            st.download_button(
                label="⬇️ Download JSON",
                data=json_data,
                file_name=f"file_categories_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
    
    with export_col3:
        if st.button("📊 Generate Report", type="secondary"):
            report_data = generate_category_report(results)
            st.download_button(
                label="⬇️ Download Report",
                data=report_data,
                file_name=f"category_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )

def display_duplicates(results):
    """Display duplicate files with professional styling"""
    st.markdown("### 🔍 Duplicate Files")
    
    if not results['duplicates']:
        st.info("✅ No duplicate files found.")
        return
    
    duplicate_rows = []
    total_wasted_space = 0
    
    for dup_group in results['duplicates']:
        group_size = dup_group['size']
        file_count = len(dup_group['files'])
        wasted_space = group_size * (file_count - 1)
        total_wasted_space += wasted_space
        
        duplicate_rows.append({
            'File Name': dup_group['name'],
            'File Count': file_count,
            'File Size': format_file_size(group_size),
            'Wasted Space': format_file_size(wasted_space),
            'Sample Path': str(dup_group['files'][0]) if dup_group['files'] else ''
        })
    
    # Enhanced summary metrics
    metric_col1, metric_col2, metric_col3 = st.columns(3)
    with metric_col1:
        st.metric("🔄 Duplicate Groups", len(results['duplicates']))
    with metric_col2:
        total_duplicate_files = sum(len(dup['files']) for dup in results['duplicates'])
        st.metric("📁 Total Duplicate Files", total_duplicate_files)
    with metric_col3:
        st.metric("💾 Wasted Space", format_file_size(total_wasted_space))
    
    # Professional duplicate files table
    df_duplicates = pd.DataFrame(duplicate_rows)
    st.dataframe(df_duplicates, use_container_width=True, height=400)
    
    # Export section
    st.markdown("#### 💾 Export Duplicate Data")
    if st.button("📄 Export Duplicates as CSV", type="secondary"):
        csv_data = export_to_csv(df_duplicates)
        st.download_button(
            label="⬇️ Download Duplicates CSV",
            data=csv_data,
            file_name=f"duplicate_files_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

def display_sms_files(results):
    """Display SMS files with professional presentation"""
    st.markdown("### 📱 SMS Files")
    
    sms_files = results.get('sms_files', [])
    
    if not sms_files:
        st.info("ℹ️ No SMS-related files found.")
        return
    
    # SMS metrics
    total_sms_size = sum(file_info['size'] for file_info in sms_files)
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("📱 SMS Files Found", len(sms_files))
    with col2:
        st.metric("💾 Total SMS Data Size", format_file_size(total_sms_size))
    
    # SMS files table
    sms_rows = []
    for file_info in sms_files:
        sms_rows.append({
            'File Name': file_info['name'],
            'File Path': str(file_info['path']),
            'Size': format_file_size(file_info['size']),
            'Extension': file_info['extension'],
            'Detection Reason': file_info.get('detection_reason', 'Extension match')
        })
    
    df_sms = pd.DataFrame(sms_rows)
    st.dataframe(df_sms, use_container_width=True, height=400)
    
    # Export SMS data
    if st.button("📄 Export SMS Files as CSV", type="secondary"):
        csv_data = export_to_csv(df_sms)
        st.download_button(
            label="⬇️ Download SMS Files CSV",
            data=csv_data,
            file_name=f"sms_files_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

def display_detailed_report(results):
    """Display comprehensive detailed report with professional filters"""
    st.markdown("### 📋 Detailed File Report")
    
    if not results.get('file_details'):
        st.info("ℹ️ No detailed file information available.")
        return
    
    # Professional search and filter interface
    st.markdown("#### 🔍 Search & Filter Options")
    search_col1, search_col2, search_col3 = st.columns(3)
    
    with search_col1:
        search_term = st.text_input("🔍 Search files:", placeholder="Enter filename or extension")
    with search_col2:
        selected_category = st.selectbox(
            "📂 Filter by category:",
            ['All'] + list(results['categories'].keys())
        )
    with search_col3:
        min_file_size = st.number_input("📏 Min file size (KB)", min_value=0, value=0)
    
    # File details table
    file_rows = []
    for file_info in results['file_details']:
        file_rows.append({
            'File Name': file_info['name'],
            'File Path': str(file_info['path']),
            'Size': format_file_size(file_info['size']),
            'Size (bytes)': file_info['size'],
            'Extension': file_info['extension'],
            'Category': file_info['category'],
            'Modified Date': file_info.get('modified_date', 'Unknown'),
            'SMS File': '✅' if file_info.get('is_sms', False) else '❌'
        })
    
    df_files = pd.DataFrame(file_rows)
    
    # Apply filters
    filtered_df = df_files.copy()
    if search_term:
        filtered_df = filtered_df[
            filtered_df['File Name'].str.contains(search_term, case=False) |
            filtered_df['Extension'].str.contains(search_term, case=False)
        ]
    
    if selected_category != 'All':
        filtered_df = filtered_df[filtered_df['Category'] == selected_category]
    
    if min_file_size > 0:
        filtered_df = filtered_df[filtered_df['Size (bytes)'] >= min_file_size * 1024]
    
    # Remove size bytes column for display
    display_df = filtered_df.drop('Size (bytes)', axis=1)
    st.dataframe(display_df, use_container_width=True, height=500)
    
    # Professional export section
    st.markdown("#### 💾 Export Complete Analysis")
    export_col1, export_col2, export_col3 = st.columns(3)
    
    with export_col1:
        if st.button("📄 Export Filtered Results", type="secondary"):
            csv_data = export_to_csv(display_df)
            st.download_button(
                label="⬇️ Download Filtered CSV",
                data=csv_data,
                file_name=f"filtered_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    
    with export_col2:
        if st.button("📊 Export Full Analysis", type="secondary"):
            full_df = df_files.drop('Size (bytes)', axis=1)
            csv_data = export_to_csv(full_df)
            st.download_button(
                label="⬇️ Download Full CSV",
                data=csv_data,
                file_name=f"complete_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    
    with export_col3:
        if st.button("📋 Generate Summary Report", type="secondary"):
            summary_report = generate_summary_report(results)
            st.download_button(
                label="⬇️ Download Summary",
                data=summary_report,
                file_name=f"analysis_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )

def generate_category_report(results):
    """Generate comprehensive category report"""
    report_lines = [
        "FILE CATEGORIZATION REPORT",
        "=" * 50,
        f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "SUMMARY:",
        f"Total files analyzed: {results['total_files']:,}",
        f"Total storage used: {format_file_size(results['total_size'])}",
        f"Categories found: {len(results['categories'])}",
        "",
        "DETAILED BREAKDOWN BY CATEGORY:",
        "-" * 50
    ]
    
    for category, data in results['categories'].items():
        avg_size = data['total_size'] / data['count'] if data['count'] > 0 else 0
        percentage = (data['count'] / results['total_files']) * 100 if results['total_files'] > 0 else 0
        
        report_lines.extend([
            f"Category: {category}",
            f"  File count: {data['count']:,} ({percentage:.1f}%)",
            f"  Total size: {format_file_size(data['total_size'])}",
            f"  Average size: {format_file_size(avg_size)}",
            f"  Extensions: {', '.join(data['extensions'])}",
            ""
        ])
    
    return "\n".join(report_lines)

def generate_summary_report(results):
    """Generate comprehensive summary report"""
    duplicate_count = len(results['duplicates']) if results['duplicates'] else 0
    sms_count = len(results.get('sms_files', []))
    
    # Calculate wasted space
    total_wasted = 0
    if results['duplicates']:
        total_wasted = sum(
            dup['size'] * (len(dup['files']) - 1) for dup in results['duplicates']
        )
    
    report_lines = [
        "COMPREHENSIVE FILE ANALYSIS SUMMARY",
        "=" * 60,
        f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "OVERALL STATISTICS:",
        f"• Total files analyzed: {results['total_files']:,}",
        f"• Total storage used: {format_file_size(results['total_size'])}",
        f"• File categories identified: {len(results['categories'])}",
        f"• Duplicate files found: {duplicate_count}",
        f"• SMS files identified: {sms_count}",
        f"• Wasted space from duplicates: {format_file_size(total_wasted)}",
        "",
        "CATEGORY BREAKDOWN:",
        "-" * 30
    ]
    
    # Sort categories by file count
    sorted_categories = sorted(
        results['categories'].items(), 
        key=lambda x: x[1]['count'], 
        reverse=True
    )
    
    for category, data in sorted_categories:
        percentage = (data['count'] / results['total_files']) * 100 if results['total_files'] > 0 else 0
        report_lines.append(
            f"• {category}: {data['count']:,} files ({percentage:.1f}%) - {format_file_size(data['total_size'])}"
        )
    
    if results['duplicates']:
        report_lines.extend([
            "",
            "DUPLICATE ANALYSIS:",
            "-" * 20,
            f"• Total duplicate groups: {len(results['duplicates'])}",
            f"• Storage efficiency: {((results['total_size'] - total_wasted) / results['total_size'] * 100):.1f}%",
        ])
    
    report_lines.extend([
        "",
        "RECOMMENDATIONS:",
        "-" * 15,
        "• Review duplicate files to free up storage space",
        "• Consider organizing files by category for better management",
        "• Regular cleanup of temporary and cache files",
        "",
        "Report generated by File Analysis & Categorization System"
    ])
    
    return "\n".join(report_lines)

if __name__ == "__main__":
    main()