import os
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime
import hashlib
from typing import List, Dict, Any, Optional, Callable
import mimetypes

class FileAnalyzer:
    """
    Comprehensive file analysis and categorization system
    """
    
    def __init__(self):
        self.file_categories = {
            'Documents': ['.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt', '.pages'],
            'Images': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.tiff', '.ico'],
            'Videos': ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.m4v', '.3gp'],
            'Audio': ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a'],
            'Archives': ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz'],
            'Spreadsheets': ['.xls', '.xlsx', '.csv', '.ods'],
            'Presentations': ['.ppt', '.pptx', '.odp', '.key'],
            'Code': ['.py', '.js', '.html', '.css', '.java', '.cpp', '.c', '.php', '.rb', '.go', '.rs'],
            'Executables': ['.exe', '.msi', '.deb', '.rpm', '.dmg', '.app'],
            'Fonts': ['.ttf', '.otf', '.woff', '.woff2', '.eot'],
            'Data': ['.json', '.xml', '.yaml', '.yml', '.sql', '.db', '.sqlite']
        }
        
        # SMS-related configuration
        self.sms_extensions = ['.xml', '.csv', '.json', '.txt', '.db', '.sqlite']
        self.sms_keywords = ['sms', 'message', 'text', 'conversation', 'chat']
        
    def configure(self, sms_extensions: Optional[List[str]] = None, sms_keywords: Optional[List[str]] = None):
        """Configure SMS detection parameters"""
        if sms_extensions:
            self.sms_extensions = [ext.strip().lower() for ext in sms_extensions if ext.strip()]
            # Ensure extensions start with dot
            self.sms_extensions = [ext if ext.startswith('.') else f'.{ext}' for ext in self.sms_extensions]
        
        if sms_keywords:
            self.sms_keywords = [keyword.strip().lower() for keyword in sms_keywords if keyword.strip()]
    
    def get_file_category(self, file_path: Path) -> str:
        """Determine file category based on extension"""
        extension = file_path.suffix.lower()
        
        for category, extensions in self.file_categories.items():
            if extension in extensions:
                return category
        
        return 'Other'
    
    def is_sms_file(self, file_path: Path) -> tuple[bool, str]:
        """Check if file is SMS-related"""
        extension = file_path.suffix.lower()
        filename_lower = file_path.name.lower()
        
        # Check extension
        if extension in self.sms_extensions:
            return True, 'Extension match'
        
        # Check filename keywords
        for keyword in self.sms_keywords:
            if keyword in filename_lower:
                return True, f'Keyword match: {keyword}'
        
        return False, ''
    
    def get_file_info(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Get comprehensive file information"""
        try:
            stat_info = file_path.stat()
            extension = file_path.suffix.lower()
            category = self.get_file_category(file_path)
            is_sms, sms_reason = self.is_sms_file(file_path)
            
            # Get modification date
            try:
                modified_date = datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            except (OSError, ValueError):
                modified_date = 'Unknown'
            
            file_info = {
                'path': file_path,
                'name': file_path.name,
                'size': stat_info.st_size,
                'extension': extension,
                'category': category,
                'modified_date': modified_date,
                'is_sms': is_sms,
                'sms_reason': sms_reason
            }
            
            return file_info
            
        except (OSError, PermissionError) as e:
            return None
    
    def scan_directory(self, directory_path: str, recursive: bool = True, 
                      include_hidden: bool = False, min_size: int = 0, 
                      max_size: float = float('inf'),
                      progress_callback: Optional[Callable] = None) -> List[Path]:
        """Scan directory for files with filtering options"""
        directory = Path(directory_path)
        files = []
        
        if not directory.exists() or not directory.is_dir():
            raise FileNotFoundError(f"Directory not found: {directory_path}")
        
        try:
            # Get all files
            if recursive:
                pattern = "**/*"
            else:
                pattern = "*"
            
            all_items = list(directory.glob(pattern))
            total_items = len(all_items)
            
            for i, item in enumerate(all_items):
                if progress_callback:
                    progress_callback(i + 1, total_items, item.name)
                
                try:
                    # Skip directories
                    if not item.is_file():
                        continue
                    
                    # Skip hidden files if not requested
                    if not include_hidden and item.name.startswith('.'):
                        continue
                    
                    # Check file size constraints
                    stat_info = item.stat()
                    if stat_info.st_size < min_size or stat_info.st_size > max_size:
                        continue
                    
                    files.append(item)
                    
                except (OSError, PermissionError):
                    # Skip files we can't access
                    continue
            
            return files
            
        except PermissionError:
            raise PermissionError(f"Permission denied accessing directory: {directory_path}")
    
    def detect_duplicates(self, file_infos: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect duplicate files based on name and size"""
        size_name_groups = defaultdict(list)
        
        # Group files by size and name
        for file_info in file_infos:
            key = (file_info['size'], file_info['name'])
            size_name_groups[key].append(file_info)
        
        # Find groups with more than one file
        duplicates = []
        for (size, name), files in size_name_groups.items():
            if len(files) > 1:
                duplicates.append({
                    'name': name,
                    'size': size,
                    'files': [file_info['path'] for file_info in files]
                })
        
        return duplicates
    
    def analyze_files(self, file_paths: List[Path], detect_duplicates: bool = True) -> Dict[str, Any]:
        """Analyze a list of files"""
        results = {
            'total_files': 0,
            'total_size': 0,
            'categories': defaultdict(lambda: {
                'count': 0,
                'total_size': 0,
                'extensions': set()
            }),
            'duplicates': [],
            'sms_files': [],
            'file_details': []
        }
        
        file_infos = []
        
        for file_path in file_paths:
            file_info = self.get_file_info(file_path)
            if file_info:
                file_infos.append(file_info)
                
                # Update totals
                results['total_files'] += 1
                results['total_size'] += file_info['size']
                
                # Update category info
                category = file_info['category']
                results['categories'][category]['count'] += 1
                results['categories'][category]['total_size'] += file_info['size']
                results['categories'][category]['extensions'].add(file_info['extension'])
                
                # Track SMS files
                if file_info['is_sms']:
                    results['sms_files'].append({
                        'path': file_info['path'],
                        'name': file_info['name'],
                        'size': file_info['size'],
                        'extension': file_info['extension'],
                        'detection_reason': file_info['sms_reason']
                    })
                
                # Add to detailed report
                results['file_details'].append(file_info)
        
        # Convert sets to lists for JSON serialization
        for category in results['categories']:
            results['categories'][category]['extensions'] = list(results['categories'][category]['extensions'])
        
        # Detect duplicates if requested
        if detect_duplicates and file_infos:
            results['duplicates'] = self.detect_duplicates(file_infos)
        
        return dict(results)
    
    def analyze_directory(self, directory_path: str, recursive: bool = True,
                         include_hidden: bool = False, min_size: int = 0,
                         max_size: float = float('inf'), detect_duplicates: bool = True,
                         progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Analyze all files in a directory"""
        
        # Scan directory for files
        files = self.scan_directory(
            directory_path, recursive, include_hidden, 
            min_size, max_size, progress_callback
        )
        
        # Analyze the found files
        return self.analyze_files(files, detect_duplicates)
