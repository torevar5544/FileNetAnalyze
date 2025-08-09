import pandas as pd
import json
from typing import Dict, Any, List
import io

def format_file_size(size_bytes: int) -> str:
    """Convert bytes to human readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    size_float = float(size_bytes)
    
    while size_float >= 1024 and i < len(size_names) - 1:
        size_float /= 1024.0
        i += 1
    
    return f"{size_float:.1f} {size_names[i]}"

def export_to_csv(dataframe: pd.DataFrame) -> str:
    """Export DataFrame to CSV string"""
    return dataframe.to_csv(index=False)

def export_to_json(data: Dict[str, Any]) -> str:
    """Export data to JSON string"""
    return json.dumps(data, indent=2, default=str)

def safe_file_path(file_path: str) -> str:
    """Sanitize file path for display"""
    try:
        return str(file_path)
    except Exception:
        return "Invalid path"

def calculate_storage_efficiency(total_size: int, duplicate_size: int) -> float:
    """Calculate storage efficiency percentage"""
    if total_size == 0:
        return 100.0
    
    efficiency = ((total_size - duplicate_size) / total_size) * 100
    return max(0.0, min(100.0, efficiency))

def get_file_type_color_map() -> Dict[str, str]:
    """Get color mapping for file types for consistent visualization"""
    return {
        'Documents': '#3498db',
        'Images': '#e74c3c',
        'Videos': '#9b59b6',
        'Audio': '#f39c12',
        'Archives': '#95a5a6',
        'Spreadsheets': '#27ae60',
        'Presentations': '#e67e22',
        'Code': '#34495e',
        'Executables': '#c0392b',
        'Fonts': '#8e44ad',
        'Data': '#16a085',
        'Other': '#7f8c8d'
    }

def create_summary_statistics(results: Dict[str, Any]) -> Dict[str, Any]:
    """Create comprehensive summary statistics"""
    stats = {
        'total_files': results.get('total_files', 0),
        'total_size_bytes': results.get('total_size', 0),
        'total_size_formatted': format_file_size(results.get('total_size', 0)),
        'categories_count': len(results.get('categories', {})),
        'duplicates_count': len(results.get('duplicates', [])),
        'sms_files_count': len(results.get('sms_files', [])),
        'largest_category': None,
        'smallest_category': None,
        'most_common_extension': None,
        'storage_efficiency': 100.0
    }
    
    categories = results.get('categories', {})
    if categories:
        # Find largest and smallest categories by file count
        largest = max(categories.items(), key=lambda x: x[1]['count'])
        smallest = min(categories.items(), key=lambda x: x[1]['count'])
        
        stats['largest_category'] = {
            'name': largest[0],
            'count': largest[1]['count'],
            'size': format_file_size(largest[1]['total_size'])
        }
        
        stats['smallest_category'] = {
            'name': smallest[0],
            'count': smallest[1]['count'],
            'size': format_file_size(smallest[1]['total_size'])
        }
        
        # Find most common extension
        all_extensions = []
        for category_data in categories.values():
            all_extensions.extend(category_data['extensions'])
        
        if all_extensions:
            from collections import Counter
            extension_counts = Counter(all_extensions)
            most_common = extension_counts.most_common(1)[0]
            stats['most_common_extension'] = {
                'extension': most_common[0],
                'count': most_common[1]
            }
    
    # Calculate storage efficiency
    duplicates = results.get('duplicates', [])
    if duplicates:
        total_duplicate_waste = sum(
            dup['size'] * (len(dup['files']) - 1) for dup in duplicates
        )
        stats['storage_efficiency'] = calculate_storage_efficiency(
            results.get('total_size', 0), total_duplicate_waste
        )
    
    return stats

def validate_directory_path(path: str) -> tuple[bool, str]:
    """Validate if directory path is accessible"""
    import os
    
    if not path:
        return False, "Path is empty"
    
    if not os.path.exists(path):
        return False, "Path does not exist"
    
    if not os.path.isdir(path):
        return False, "Path is not a directory"
    
    if not os.access(path, os.R_OK):
        return False, "Permission denied: Cannot read directory"
    
    return True, "Valid directory path"

def estimate_analysis_time(file_count: int) -> str:
    """Estimate analysis time based on file count"""
    if file_count < 100:
        return "< 1 minute"
    elif file_count < 1000:
        return "1-2 minutes"
    elif file_count < 10000:
        return "2-5 minutes"
    elif file_count < 50000:
        return "5-15 minutes"
    else:
        return "15+ minutes"

def create_analysis_report_summary(results: Dict[str, Any]) -> str:
    """Create a text summary of the analysis results"""
    stats = create_summary_statistics(results)
    
    summary_lines = [
        "FILE ANALYSIS REPORT SUMMARY",
        "=" * 40,
        f"Total Files Analyzed: {stats['total_files']:,}",
        f"Total Storage Used: {stats['total_size_formatted']}",
        f"File Categories Found: {stats['categories_count']}",
        f"Duplicate Files Found: {stats['duplicates_count']}",
        f"SMS Files Identified: {stats['sms_files_count']}",
        f"Storage Efficiency: {stats['storage_efficiency']:.1f}%",
        ""
    ]
    
    if stats['largest_category']:
        summary_lines.extend([
            f"Largest Category: {stats['largest_category']['name']} "
            f"({stats['largest_category']['count']} files, {stats['largest_category']['size']})",
        ])
    
    if stats['most_common_extension']:
        summary_lines.extend([
            f"Most Common Extension: {stats['most_common_extension']['extension']} "
            f"({stats['most_common_extension']['count']} files)",
        ])
    
    summary_lines.extend([
        "",
        f"Report Generated: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 40
    ])
    
    return "\n".join(summary_lines)
