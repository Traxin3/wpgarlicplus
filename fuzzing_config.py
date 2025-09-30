"""
Configuration system for wpgarlic feedback-guided fuzzing.
Provides flexible configuration for fuzzing parameters and strategies.
"""

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from enum import Enum
from pathlib import Path


class FuzzingMode(Enum):
    """Different fuzzing modes."""
    FAST = "fast"
    BALANCED = "balanced"
    DEEP = "deep"
    CUSTOM = "custom"


class MutationStrategy(Enum):
    """Mutation strategies."""
    BIT_FLIP = "bit_flip"
    ARITHMETIC = "arithmetic"
    DICTIONARY = "dictionary"
    HAVOC = "havoc"
    SPLICE = "splice"
    INTERESTING = "interesting"


class CrashSeverity(Enum):
    """Crash severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class MutationConfig:
    """Configuration for mutation strategies."""
    bit_flip_probability: float = 0.2
    arithmetic_probability: float = 0.15
    dictionary_probability: float = 0.2
    havoc_probability: float = 0.25
    splice_probability: float = 0.1
    interesting_probability: float = 0.1
    
    # Bit flip settings
    bit_flip_min_bits: int = 1
    bit_flip_max_bits: int = 8
    
    # Arithmetic settings
    arithmetic_values: List[int] = field(default_factory=lambda: [
        -1, 0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128,
        255, 256, 32767, 32768, 65535, 65536, 2147483647, 2147483648
    ])
    
    # Dictionary settings
    dictionary_size: int = 100
    dictionary_custom: List[str] = field(default_factory=list)
    
    # Havoc settings
    havoc_min_ops: int = 1
    havoc_max_ops: int = 5
    
    # Splice settings
    splice_min_length: int = 10
    splice_max_length: int = 1000


@dataclass
class CoverageConfig:
    """Configuration for coverage tracking."""
    enable_coverage: bool = True
    coverage_granularity: str = "line"  # line, function, block
    coverage_threshold: float = 0.01
    coverage_timeout: int = 30
    
    # Coverage tracking settings
    track_branches: bool = True
    track_functions: bool = True
    track_files: bool = True
    
    # Performance settings
    max_coverage_points: int = 100000
    coverage_snapshot_interval: int = 100
    
    # File filtering
    include_patterns: List[str] = field(default_factory=lambda: ["*.php"])
    exclude_patterns: List[str] = field(default_factory=lambda: [
        "*/vendor/*", "*/node_modules/*", "*/.git/*", "*/test/*", "*/tests/*"
    ])


@dataclass
class CrashConfig:
    """Configuration for crash detection and analysis."""
    enable_crash_detection: bool = True
    crash_dedup_threshold: float = 0.8
    crash_severity_threshold: CrashSeverity = CrashSeverity.LOW
    
    # Crash patterns
    fatal_error_patterns: List[str] = field(default_factory=lambda: [
        "fatal error", "fatal exception", "segmentation fault", "stack overflow"
    ])
    
    sql_injection_patterns: List[str] = field(default_factory=lambda: [
        "sql syntax", "mysql error", "database error", "query failed"
    ])
    
    xss_patterns: List[str] = field(default_factory=lambda: [
        "<script>", "javascript:", "onload=", "onerror=", "onclick="
    ])
    
    file_inclusion_patterns: List[str] = field(default_factory=lambda: [
        "include", "require", "file_get_contents", "fopen"
    ])
    
    # Crash analysis
    analyze_stack_traces: bool = True
    analyze_memory_dumps: bool = False
    crash_report_format: str = "json"  # json, html, text


@dataclass
class PerformanceConfig:
    """Configuration for performance and resource management."""
    max_executions: int = 100000
    max_test_cases: int = 10000
    max_execution_time: int = 30
    max_memory_usage: int = 512 * 1024 * 1024  # 512MB
    
    # Resource limits
    cpu_limit: float = 80.0  # CPU usage percentage
    memory_limit: float = 80.0  # Memory usage percentage
    
    # Performance optimization
    enable_parallel_execution: bool = False
    max_parallel_jobs: int = 4
    execution_timeout: int = 10
    
    # Statistics
    stats_update_interval: int = 1
    detailed_logging: bool = True


@dataclass
class OutputConfig:
    """Configuration for output and reporting."""
    output_directory: str = "fuzzing_results"
    save_intermediate_results: bool = True
    save_coverage_reports: bool = True
    save_crash_reports: bool = True
    
    # Report formats
    report_formats: List[str] = field(default_factory=lambda: ["json", "html"])
    
    # Logging
    log_level: str = "INFO"  # DEBUG, INFO, WARNING, ERROR
    log_file: str = "fuzzing.log"
    console_output: bool = True
    
    # Real-time updates
    real_time_stats: bool = True
    progress_bar: bool = True
    live_coverage: bool = True


@dataclass
class WordPressConfig:
    """WordPress-specific configuration."""
    wp_version: str = "latest"
    wp_debug: bool = True
    wp_debug_log: bool = True
    
    # Plugin/Theme settings
    target_type: str = "plugin"  # plugin, theme
    target_slug: str = ""
    target_version: str = ""
    
    # WordPress features to fuzz
    fuzz_ajax_actions: bool = True
    fuzz_rest_endpoints: bool = True
    fuzz_admin_pages: bool = True
    fuzz_shortcodes: bool = True
    fuzz_hooks: bool = True
    
    # User roles to test
    test_roles: List[str] = field(default_factory=lambda: ["subscriber", "administrator"])
    
    # WordPress-specific patterns
    wp_functions: List[str] = field(default_factory=lambda: [
        "wp_insert_post", "wp_update_post", "wp_delete_post",
        "add_action", "add_filter", "wp_enqueue_script",
        "wp_enqueue_style", "get_option", "update_option"
    ])
    
    # Security features
    enable_nonce_validation: bool = True
    enable_capability_checks: bool = True
    sanitize_inputs: bool = False  # Set to False for fuzzing


@dataclass
class FuzzingConfiguration:
    """Main configuration class for wpgarlic fuzzing."""
    mode: FuzzingMode = FuzzingMode.BALANCED
    
    # Sub-configurations
    mutation: MutationConfig = field(default_factory=MutationConfig)
    coverage: CoverageConfig = field(default_factory=CoverageConfig)
    crash: CrashConfig = field(default_factory=CrashConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    wordpress: WordPressConfig = field(default_factory=WordPressConfig)
    
    # Global settings
    seed: Optional[int] = None
    resume_from_checkpoint: bool = False
    checkpoint_interval: int = 1000
    
    def __post_init__(self):
        """Post-initialization setup."""
        if self.seed is None:
            import random
            self.seed = random.randint(1, 2**32)
        
        # Create output directory
        os.makedirs(self.output.output_directory, exist_ok=True)


class ConfigurationManager:
    """Manager for fuzzing configurations."""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file
        self.config = FuzzingConfiguration()
        
        if config_file and os.path.exists(config_file):
            self.load_config(config_file)
    
    def create_preset_config(self, mode: FuzzingMode) -> FuzzingConfiguration:
        """Create a configuration preset for a specific mode."""
        config = FuzzingConfiguration(mode=mode)
        
        if mode == FuzzingMode.FAST:
            # Fast mode: Quick fuzzing with minimal coverage
            config.performance.max_executions = 10000
            config.performance.max_test_cases = 1000
            config.performance.max_execution_time = 5
            config.coverage.coverage_snapshot_interval = 50
            config.mutation.havoc_probability = 0.4
            config.mutation.bit_flip_probability = 0.3
            
        elif mode == FuzzingMode.BALANCED:
            # Balanced mode: Good balance of speed and thoroughness
            config.performance.max_executions = 50000
            config.performance.max_test_cases = 5000
            config.performance.max_execution_time = 15
            config.coverage.coverage_snapshot_interval = 100
            
        elif mode == FuzzingMode.DEEP:
            # Deep mode: Thorough fuzzing with extensive coverage
            config.performance.max_executions = 200000
            config.performance.max_test_cases = 20000
            config.performance.max_execution_time = 30
            config.coverage.coverage_snapshot_interval = 50
            config.coverage.track_branches = True
            config.coverage.track_functions = True
            config.crash.analyze_stack_traces = True
            # Adjust probabilities to sum to 1.0
            config.mutation.splice_probability = 0.15
            config.mutation.dictionary_probability = 0.25
            config.mutation.bit_flip_probability = 0.2
            config.mutation.arithmetic_probability = 0.15
            config.mutation.havoc_probability = 0.2
            config.mutation.interesting_probability = 0.05
        
        return config
    
    def load_config(self, config_file: str) -> FuzzingConfiguration:
        """Load configuration from file."""
        with open(config_file, 'r') as f:
            data = json.load(f)
        
        # Convert string enums back to enum objects
        if 'mode' in data:
            data['mode'] = FuzzingMode(data['mode'])
        
        # Load sub-configurations
        for section in ['mutation', 'coverage', 'crash', 'performance', 'output', 'wordpress']:
            if section in data:
                section_data = data[section]
                
                # Convert enum values
                if section == 'crash' and 'crash_severity_threshold' in section_data:
                    section_data['crash_severity_threshold'] = CrashSeverity(section_data['crash_severity_threshold'])
                
                # Create the configuration object
                if section == "wordpress":
                    section_class = WordPressConfig
                else:
                    section_class = globals()[f"{section.title()}Config"]
                section_config = section_class(**section_data)
                setattr(self.config, section, section_config)
        
        # Set other attributes
        for key, value in data.items():
            if key not in ['mutation', 'coverage', 'crash', 'performance', 'output', 'wordpress']:
                setattr(self.config, key, value)
        
        return self.config
    
    def save_config(self, config_file: str, config: FuzzingConfiguration = None):
        """Save configuration to file."""
        if config is None:
            config = self.config
        
        data = {
            'mode': config.mode.value,
            'seed': config.seed,
            'resume_from_checkpoint': config.resume_from_checkpoint,
            'checkpoint_interval': config.checkpoint_interval,
            
            # Sub-configurations
            'mutation': {
                'bit_flip_probability': config.mutation.bit_flip_probability,
                'arithmetic_probability': config.mutation.arithmetic_probability,
                'dictionary_probability': config.mutation.dictionary_probability,
                'havoc_probability': config.mutation.havoc_probability,
                'splice_probability': config.mutation.splice_probability,
                'interesting_probability': config.mutation.interesting_probability,
                'bit_flip_min_bits': config.mutation.bit_flip_min_bits,
                'bit_flip_max_bits': config.mutation.bit_flip_max_bits,
                'arithmetic_values': config.mutation.arithmetic_values,
                'dictionary_size': config.mutation.dictionary_size,
                'dictionary_custom': config.mutation.dictionary_custom,
                'havoc_min_ops': config.mutation.havoc_min_ops,
                'havoc_max_ops': config.mutation.havoc_max_ops,
                'splice_min_length': config.mutation.splice_min_length,
                'splice_max_length': config.mutation.splice_max_length,
            },
            
            'coverage': {
                'enable_coverage': config.coverage.enable_coverage,
                'coverage_granularity': config.coverage.coverage_granularity,
                'coverage_threshold': config.coverage.coverage_threshold,
                'coverage_timeout': config.coverage.coverage_timeout,
                'track_branches': config.coverage.track_branches,
                'track_functions': config.coverage.track_functions,
                'track_files': config.coverage.track_files,
                'max_coverage_points': config.coverage.max_coverage_points,
                'coverage_snapshot_interval': config.coverage.coverage_snapshot_interval,
                'include_patterns': config.coverage.include_patterns,
                'exclude_patterns': config.coverage.exclude_patterns,
            },
            
            'crash': {
                'enable_crash_detection': config.crash.enable_crash_detection,
                'crash_dedup_threshold': config.crash.crash_dedup_threshold,
                'crash_severity_threshold': config.crash.crash_severity_threshold.value,
                'fatal_error_patterns': config.crash.fatal_error_patterns,
                'sql_injection_patterns': config.crash.sql_injection_patterns,
                'xss_patterns': config.crash.xss_patterns,
                'file_inclusion_patterns': config.crash.file_inclusion_patterns,
                'analyze_stack_traces': config.crash.analyze_stack_traces,
                'analyze_memory_dumps': config.crash.analyze_memory_dumps,
                'crash_report_format': config.crash.crash_report_format,
            },
            
            'performance': {
                'max_executions': config.performance.max_executions,
                'max_test_cases': config.performance.max_test_cases,
                'max_execution_time': config.performance.max_execution_time,
                'max_memory_usage': config.performance.max_memory_usage,
                'cpu_limit': config.performance.cpu_limit,
                'memory_limit': config.performance.memory_limit,
                'enable_parallel_execution': config.performance.enable_parallel_execution,
                'max_parallel_jobs': config.performance.max_parallel_jobs,
                'execution_timeout': config.performance.execution_timeout,
                'stats_update_interval': config.performance.stats_update_interval,
                'detailed_logging': config.performance.detailed_logging,
            },
            
            'output': {
                'output_directory': config.output.output_directory,
                'save_intermediate_results': config.output.save_intermediate_results,
                'save_coverage_reports': config.output.save_coverage_reports,
                'save_crash_reports': config.output.save_crash_reports,
                'report_formats': config.output.report_formats,
                'log_level': config.output.log_level,
                'log_file': config.output.log_file,
                'console_output': config.output.console_output,
                'real_time_stats': config.output.real_time_stats,
                'progress_bar': config.output.progress_bar,
                'live_coverage': config.output.live_coverage,
            },
            
            'wordpress': {
                'wp_version': config.wordpress.wp_version,
                'wp_debug': config.wordpress.wp_debug,
                'wp_debug_log': config.wordpress.wp_debug_log,
                'target_type': config.wordpress.target_type,
                'target_slug': config.wordpress.target_slug,
                'target_version': config.wordpress.target_version,
                'fuzz_ajax_actions': config.wordpress.fuzz_ajax_actions,
                'fuzz_rest_endpoints': config.wordpress.fuzz_rest_endpoints,
                'fuzz_admin_pages': config.wordpress.fuzz_admin_pages,
                'fuzz_shortcodes': config.wordpress.fuzz_shortcodes,
                'fuzz_hooks': config.wordpress.fuzz_hooks,
                'test_roles': config.wordpress.test_roles,
                'wp_functions': config.wordpress.wp_functions,
                'enable_nonce_validation': config.wordpress.enable_nonce_validation,
                'enable_capability_checks': config.wordpress.enable_capability_checks,
                'sanitize_inputs': config.wordpress.sanitize_inputs,
            }
        }
        
        with open(config_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Get a summary of the current configuration."""
        return {
            'mode': self.config.mode.value,
            'max_executions': self.config.performance.max_executions,
            'max_test_cases': self.config.performance.max_test_cases,
            'coverage_enabled': self.config.coverage.enable_coverage,
            'crash_detection_enabled': self.config.crash.enable_crash_detection,
            'output_directory': self.config.output.output_directory,
            'target_type': self.config.wordpress.target_type,
            'target_slug': self.config.wordpress.target_slug
        }
    
    def validate_config(self) -> List[str]:
        """Validate the current configuration and return any issues."""
        issues = []
        
        # Validate performance settings
        if self.config.performance.max_executions <= 0:
            issues.append("max_executions must be greater than 0")
        
        if self.config.performance.max_test_cases <= 0:
            issues.append("max_test_cases must be greater than 0")
        
        if self.config.performance.max_execution_time <= 0:
            issues.append("max_execution_time must be greater than 0")
        
        # Validate mutation probabilities
        total_prob = (
            self.config.mutation.bit_flip_probability +
            self.config.mutation.arithmetic_probability +
            self.config.mutation.dictionary_probability +
            self.config.mutation.havoc_probability +
            self.config.mutation.splice_probability +
            self.config.mutation.interesting_probability
        )
        
        if abs(total_prob - 1.0) > 0.01:
            issues.append(f"Mutation probabilities sum to {total_prob}, should be 1.0")
        
        # Validate WordPress settings
        if not self.config.wordpress.target_slug:
            issues.append("WordPress target_slug is required")
        
        # Validate output directory
        if not os.path.exists(self.config.output.output_directory):
            try:
                os.makedirs(self.config.output.output_directory, exist_ok=True)
            except Exception as e:
                issues.append(f"Cannot create output directory: {e}")
        
        return issues


def create_default_config(mode: FuzzingMode = FuzzingMode.BALANCED) -> FuzzingConfiguration:
    """Create a default configuration for the specified mode."""
    manager = ConfigurationManager()
    return manager.create_preset_config(mode)


def load_config_file(config_file: str) -> FuzzingConfiguration:
    """Load configuration from a file."""
    manager = ConfigurationManager(config_file)
    return manager.config


def save_config_file(config: FuzzingConfiguration, config_file: str):
    """Save configuration to a file."""
    manager = ConfigurationManager()
    manager.save_config(config_file, config)
