"""
Enhanced coverage tracking system for WordPress plugin fuzzing.
Provides detailed code coverage analysis and path tracking.
"""

import json
import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from pathlib import Path

import psutil


@dataclass
class CoveragePoint:
    """Represents a single coverage point."""
    file_path: str
    line_number: int
    function_name: Optional[str] = None
    branch_id: Optional[str] = None
    hit_count: int = 0
    first_hit_time: float = 0.0
    last_hit_time: float = 0.0


@dataclass
class FunctionCoverage:
    """Coverage information for a function."""
    function_name: str
    file_path: str
    start_line: int
    end_line: int
    lines_hit: Set[int] = field(default_factory=set)
    branches_hit: Set[str] = field(default_factory=set)
    execution_count: int = 0
    complexity: int = 0


@dataclass
class FileCoverage:
    """Coverage information for a file."""
    file_path: str
    total_lines: int = 0
    executable_lines: int = 0
    lines_hit: Set[int] = field(default_factory=set)
    functions: Dict[str, FunctionCoverage] = field(default_factory=dict)
    branches: Dict[str, Set[str]] = field(default_factory=dict)
    coverage_percentage: float = 0.0


@dataclass
class CoverageSnapshot:
    """Snapshot of coverage at a specific time."""
    timestamp: float
    total_coverage: int
    unique_paths: Set[str]
    file_coverage: Dict[str, FileCoverage]
    execution_time: float
    memory_usage: int


class CoverageTracker:
    """Enhanced coverage tracking system."""
    
    def __init__(self, plugin_path: str, output_dir: str = "coverage_data"):
        self.plugin_path = plugin_path
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Coverage data
        self.coverage_points: Dict[str, CoveragePoint] = {}
        self.file_coverage: Dict[str, FileCoverage] = {}
        self.function_coverage: Dict[str, FunctionCoverage] = {}
        self.path_coverage: Set[str] = set()
        
        # Execution tracking
        self.execution_times: List[float] = []
        self.memory_usage: List[int] = []
        self.coverage_history: List[CoverageSnapshot] = []
        
        # Performance metrics
        self.start_time = time.time()
        self.total_executions = 0
        
        # Initialize coverage tracking
        self._initialize_coverage_tracking()
        
    def _initialize_coverage_tracking(self):
        """Initialize coverage tracking for the plugin."""
        # Find all PHP files in the plugin
        php_files = self._find_php_files()
        
        for file_path in php_files:
            self._analyze_file(file_path)
    
    def _find_php_files(self) -> List[str]:
        """Find all PHP files in the plugin directory."""
        php_files = []
        
        for root, dirs, files in os.walk(self.plugin_path):
            # Skip certain directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['vendor', 'node_modules']]
            
            for file in files:
                if file.endswith('.php'):
                    php_files.append(os.path.join(root, file))
        
        return php_files
    
    def _analyze_file(self, file_path: str):
        """Analyze a PHP file for coverage tracking."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Create file coverage object
            file_cov = FileCoverage(file_path=file_path)
            
            # Parse functions and coverage points
            functions = self._parse_functions(content, file_path)
            coverage_points = self._parse_coverage_points(content, file_path)
            
            file_cov.functions = functions
            file_cov.executable_lines = len(coverage_points)
            file_cov.total_lines = len(content.splitlines())
            
            # Store coverage points
            for point in coverage_points:
                self.coverage_points[f"{file_path}:{point.line_number}"] = point
            
            # Store file coverage
            self.file_coverage[file_path] = file_cov
            
        except Exception as e:
            print(f"Error analyzing file {file_path}: {e}")
    
    def _parse_functions(self, content: str, file_path: str) -> Dict[str, FunctionCoverage]:
        """Parse functions from PHP file content."""
        functions = {}
        
        # Function regex patterns
        function_patterns = [
            r'function\s+(\w+)\s*\([^)]*\)\s*\{',
            r'class\s+(\w+)[^{]*\{',
            r'public\s+function\s+(\w+)\s*\([^)]*\)\s*\{',
            r'private\s+function\s+(\w+)\s*\([^)]*\)\s*\{',
            r'protected\s+function\s+(\w+)\s*\([^)]*\)\s*\{',
            r'static\s+function\s+(\w+)\s*\([^)]*\)\s*\{',
        ]
        
        lines = content.splitlines()
        
        for i, line in enumerate(lines):
            for pattern in function_patterns:
                match = re.search(pattern, line)
                if match:
                    function_name = match.group(1)
                    start_line = i + 1
                    
                    # Find function end (simplified)
                    end_line = self._find_function_end(lines, start_line)
                    
                    func_cov = FunctionCoverage(
                        function_name=function_name,
                        file_path=file_path,
                        start_line=start_line,
                        end_line=end_line
                    )
                    
                    functions[function_name] = func_cov
        
        return functions
    
    def _find_function_end(self, lines: List[str], start_line: int) -> int:
        """Find the end line of a function."""
        brace_count = 0
        in_function = False
        
        for i in range(start_line - 1, len(lines)):
            line = lines[i]
            
            if '{' in line:
                brace_count += line.count('{')
                in_function = True
            elif '}' in line:
                brace_count -= line.count('}')
                
                if in_function and brace_count == 0:
                    return i + 1
        
        return len(lines)
    
    def _parse_coverage_points(self, content: str, file_path: str) -> List[CoveragePoint]:
        """Parse executable lines for coverage tracking."""
        coverage_points = []
        lines = content.splitlines()
        
        for i, line in enumerate(lines):
            line_num = i + 1
            line = line.strip()
            
            # Skip empty lines, comments, and declarations
            if (not line or 
                line.startswith('//') or 
                line.startswith('/*') or 
                line.startswith('*') or
                line.startswith('#') or
                line.endswith(';') and not any(keyword in line for keyword in 
                    ['if', 'while', 'for', 'foreach', 'switch', 'case', 'return', 'echo', 'print'])):
                continue
            
            # Check if line is executable
            if self._is_executable_line(line):
                point = CoveragePoint(
                    file_path=file_path,
                    line_number=line_num
                )
                coverage_points.append(point)
        
        return coverage_points
    
    def _is_executable_line(self, line: str) -> bool:
        """Check if a line is executable."""
        executable_patterns = [
            r'\$[a-zA-Z_][a-zA-Z0-9_]*\s*=.*',  # Variable assignment
            r'if\s*\(',  # If statements
            r'else\s*\{?',  # Else statements
            r'while\s*\(',  # While loops
            r'for\s*\(',  # For loops
            r'foreach\s*\(',  # Foreach loops
            r'switch\s*\(',  # Switch statements
            r'case\s+',  # Case statements
            r'return\s+',  # Return statements
            r'echo\s+',  # Echo statements
            r'print\s+',  # Print statements
            r'function\s+\w+\s*\(',  # Function definitions
            r'class\s+\w+',  # Class definitions
            r'include\s+',  # Include statements
            r'require\s+',  # Require statements
            r'wp_',  # WordPress functions
            r'add_action\s*\(',  # WordPress hooks
            r'add_filter\s*\(',  # WordPress filters
        ]
        
        for pattern in executable_patterns:
            if re.search(pattern, line):
                return True
        
        return False
    
    def record_execution(self, output: str, execution_time: float, memory_usage: int = 0):
        """Record execution results and update coverage."""
        self.total_executions += 1
        self.execution_times.append(execution_time)
        self.memory_usage.append(memory_usage)
        
        # Parse coverage information from output
        coverage_info = self._parse_coverage_output(output)
        
        # Update coverage points
        for file_path, lines in coverage_info.items():
            if file_path in self.file_coverage:
                for line_num in lines:
                    point_key = f"{file_path}:{line_num}"
                    if point_key in self.coverage_points:
                        point = self.coverage_points[point_key]
                        point.hit_count += 1
                        if point.first_hit_time == 0:
                            point.first_hit_time = time.time()
                        point.last_hit_time = time.time()
                        
                        # Update file coverage
                        self.file_coverage[file_path].lines_hit.add(line_num)
        
        # Update path coverage
        path_signature = self._generate_path_signature(coverage_info)
        self.path_coverage.add(path_signature)
        
        # Update coverage percentages
        self._update_coverage_percentages()
        
        # Create snapshot periodically
        if self.total_executions % 100 == 0:
            self._create_snapshot()
    
    def _parse_coverage_output(self, output: str) -> Dict[str, Set[int]]:
        """Parse coverage information from execution output."""
        coverage_info = defaultdict(set)
        
        # Look for coverage markers in output
        # This would be enhanced by instrumenting the PHP code
        coverage_patterns = [
            r'__COVERAGE__\s+([^:]+):(\d+)__',
            r'__HIT__\s+([^:]+):(\d+)__',
            r'file:([^,]+),line:(\d+)',
        ]
        
        for pattern in coverage_patterns:
            matches = re.findall(pattern, output)
            for match in matches:
                file_path = match[0]
                line_num = int(match[1])
                coverage_info[file_path].add(line_num)
        
        return dict(coverage_info)
    
    def _generate_path_signature(self, coverage_info: Dict[str, Set[int]]) -> str:
        """Generate a unique signature for the execution path."""
        # Create a sorted list of covered files and lines
        path_elements = []
        for file_path, lines in sorted(coverage_info.items()):
            file_name = os.path.basename(file_path)
            path_elements.append(f"{file_name}:{sorted(lines)}")
        
        return "|".join(path_elements)
    
    def _update_coverage_percentages(self):
        """Update coverage percentages for all files."""
        for file_path, file_cov in self.file_coverage.items():
            if file_cov.executable_lines > 0:
                file_cov.coverage_percentage = (len(file_cov.lines_hit) / file_cov.executable_lines) * 100
    
    def _create_snapshot(self):
        """Create a coverage snapshot."""
        snapshot = CoverageSnapshot(
            timestamp=time.time(),
            total_coverage=len(self.coverage_points),
            unique_paths=self.path_coverage.copy(),
            file_coverage=self.file_coverage.copy(),
            execution_time=sum(self.execution_times) / len(self.execution_times) if self.execution_times else 0,
            memory_usage=sum(self.memory_usage) / len(self.memory_usage) if self.memory_usage else 0
        )
        
        self.coverage_history.append(snapshot)
        
        # Keep only recent snapshots
        if len(self.coverage_history) > 1000:
            self.coverage_history = self.coverage_history[-1000:]
    
    def get_coverage_summary(self) -> Dict[str, Any]:
        """Get a summary of current coverage."""
        total_executable_lines = sum(fc.executable_lines for fc in self.file_coverage.values())
        total_lines_hit = sum(len(fc.lines_hit) for fc in self.file_coverage.values())
        
        overall_percentage = (total_lines_hit / total_executable_lines * 100) if total_executable_lines > 0 else 0
        
        # Top files by coverage
        file_stats = []
        for file_path, file_cov in self.file_coverage.items():
            if file_cov.executable_lines > 0:
                file_stats.append({
                    'file': os.path.basename(file_path),
                    'percentage': file_cov.coverage_percentage,
                    'lines_hit': len(file_cov.lines_hit),
                    'executable_lines': file_cov.executable_lines
                })
        
        file_stats.sort(key=lambda x: x['percentage'], reverse=True)
        
        return {
            'overall_percentage': overall_percentage,
            'total_executable_lines': total_executable_lines,
            'total_lines_hit': total_lines_hit,
            'unique_paths': len(self.path_coverage),
            'total_executions': self.total_executions,
            'top_files': file_stats[:10],
            'average_execution_time': sum(self.execution_times) / len(self.execution_times) if self.execution_times else 0,
            'average_memory_usage': sum(self.memory_usage) / len(self.memory_usage) if self.memory_usage else 0
        }
    
    def get_new_coverage(self, previous_coverage: Set[str]) -> Set[str]:
        """Get new coverage since the last check."""
        return self.path_coverage - previous_coverage
    
    def get_coverage_growth_rate(self) -> float:
        """Calculate coverage growth rate."""
        if len(self.coverage_history) < 2:
            return 0.0
        
        recent = self.coverage_history[-1]
        older = self.coverage_history[-10] if len(self.coverage_history) >= 10 else self.coverage_history[0]
        
        time_diff = recent.timestamp - older.timestamp
        coverage_diff = len(recent.unique_paths) - len(older.unique_paths)
        
        return coverage_diff / time_diff if time_diff > 0 else 0.0
    
    def save_coverage_report(self, output_file: str = None):
        """Save detailed coverage report."""
        if output_file is None:
            output_file = os.path.join(self.output_dir, f"coverage_report_{int(time.time())}.json")
        
        report = {
            'summary': self.get_coverage_summary(),
            'file_coverage': {
                path: {
                    'total_lines': fc.total_lines,
                    'executable_lines': fc.executable_lines,
                    'lines_hit': list(fc.lines_hit),
                    'coverage_percentage': fc.coverage_percentage,
                    'functions': {
                        name: {
                            'start_line': func.start_line,
                            'end_line': func.end_line,
                            'lines_hit': list(func.lines_hit),
                            'execution_count': func.execution_count
                        } for name, func in fc.functions.items()
                    }
                } for path, fc in self.file_coverage.items()
            },
            'coverage_points': {
                key: {
                    'file_path': point.file_path,
                    'line_number': point.line_number,
                    'hit_count': point.hit_count,
                    'first_hit_time': point.first_hit_time,
                    'last_hit_time': point.last_hit_time
                } for key, point in self.coverage_points.items()
            },
            'path_coverage': list(self.path_coverage),
            'execution_stats': {
                'total_executions': self.total_executions,
                'average_execution_time': sum(self.execution_times) / len(self.execution_times) if self.execution_times else 0,
                'average_memory_usage': sum(self.memory_usage) / len(self.memory_usage) if self.memory_usage else 0,
                'execution_times': self.execution_times[-100:],  # Last 100 executions
                'memory_usage': self.memory_usage[-100:]  # Last 100 executions
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        return output_file
    
    def load_coverage_report(self, input_file: str):
        """Load coverage report from file."""
        with open(input_file, 'r') as f:
            report = json.load(f)
        
        # Restore coverage data
        self.file_coverage = {}
        self.coverage_points = {}
        self.path_coverage = set(report['path_coverage'])
        
        for path, data in report['file_coverage'].items():
            fc = FileCoverage(
                file_path=path,
                total_lines=data['total_lines'],
                executable_lines=data['executable_lines'],
                lines_hit=set(data['lines_hit']),
                coverage_percentage=data['coverage_percentage']
            )
            
            # Restore functions
            for name, func_data in data['functions'].items():
                func = FunctionCoverage(
                    function_name=name,
                    file_path=path,
                    start_line=func_data['start_line'],
                    end_line=func_data['end_line'],
                    lines_hit=set(func_data['lines_hit']),
                    execution_count=func_data['execution_count']
                )
                fc.functions[name] = func
            
            self.file_coverage[path] = fc
        
        # Restore coverage points
        for key, data in report['coverage_points'].items():
            point = CoveragePoint(
                file_path=data['file_path'],
                line_number=data['line_number'],
                hit_count=data['hit_count'],
                first_hit_time=data['first_hit_time'],
                last_hit_time=data['last_hit_time']
            )
            self.coverage_points[key] = point
        
        # Restore execution stats
        stats = report['execution_stats']
        self.total_executions = stats['total_executions']
        self.execution_times = stats.get('execution_times', [])
        self.memory_usage = stats.get('memory_usage', [])
    
    def get_memory_usage(self) -> int:
        """Get current memory usage."""
        process = psutil.Process()
        return process.memory_info().rss
    
    def cleanup(self):
        """Cleanup resources."""
        # Save final report
        self.save_coverage_report()
        
        # Clear large data structures
        self.coverage_history.clear()
        self.execution_times.clear()
        self.memory_usage.clear()
