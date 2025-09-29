"""
Enhanced crash analysis system for wpgarlic fuzzing.
Provides advanced crash detection, deduplication, and severity classification.
"""

import hashlib
import json
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel


class CrashType(Enum):
    """Types of crashes that can be detected."""
    FATAL_ERROR = "fatal_error"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    FILE_INCLUSION = "file_inclusion"
    COMMAND_INJECTION = "command_injection"
    MEMORY_ERROR = "memory_error"
    STACK_OVERFLOW = "stack_overflow"
    DIVISION_BY_ZERO = "division_by_zero"
    TYPE_ERROR = "type_error"
    UNKNOWN = "unknown"


class CrashSeverity(Enum):
    """Crash severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CrashPattern:
    """Pattern for detecting specific types of crashes."""
    pattern: str
    crash_type: CrashType
    severity: CrashSeverity
    description: str
    regex: re.Pattern = field(init=False)
    
    def __post_init__(self):
        self.regex = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)


@dataclass
class CrashInfo:
    """Information about a detected crash."""
    signature: str
    crash_type: CrashType
    severity: CrashSeverity
    payload: str
    output: str
    stack_trace: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    function_name: Optional[str] = None
    confidence: float = 0.0
    exploitability: str = "unknown"
    cwe_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_exploitable(self) -> bool:
        """Determine if the crash appears exploitable."""
        return self.exploitability in ["high", "medium"] and self.severity in [
            CrashSeverity.HIGH, CrashSeverity.CRITICAL
        ]


class EnhancedCrashAnalyzer:
    """Enhanced crash analysis system."""
    
    def __init__(self, console: Console = None):
        self.console = console or Console()
        
        # Crash patterns
        self.crash_patterns = self._initialize_crash_patterns()
        
        # Crash tracking
        self.crashes: Dict[str, CrashInfo] = {}
        self.crash_signatures: Set[str] = set()
        self.crash_stats = defaultdict(int)
        
        # Deduplication
        self.similarity_threshold = 0.8
        self.crash_clusters: Dict[str, List[str]] = defaultdict(list)
        
        # Performance tracking
        self.analysis_times: List[float] = []
        
    def _initialize_crash_patterns(self) -> List[CrashPattern]:
        """Initialize crash detection patterns."""
        patterns = [
            # Fatal errors
            CrashPattern(
                pattern=r"Fatal error: (.+?) in (.+?) on line (\d+)",
                crash_type=CrashType.FATAL_ERROR,
                severity=CrashSeverity.HIGH,
                description="PHP Fatal Error"
            ),
            
            CrashPattern(
                pattern=r"Fatal error: Uncaught (.+?): (.+?) in (.+?) on line (\d+)",
                crash_type=CrashType.FATAL_ERROR,
                severity=CrashSeverity.HIGH,
                description="Uncaught Exception"
            ),
            
            # SQL injection
            CrashPattern(
                pattern=r"SQL syntax.*error.*near.*GARLIC",
                crash_type=CrashType.SQL_INJECTION,
                severity=CrashSeverity.HIGH,
                description="SQL Syntax Error with Payload"
            ),
            
            CrashPattern(
                pattern=r"MySQL server has gone away",
                crash_type=CrashType.SQL_INJECTION,
                severity=CrashSeverity.MEDIUM,
                description="MySQL Connection Error"
            ),
            
            CrashPattern(
                pattern=r"Unknown column.*GARLIC.*in.*field list",
                crash_type=CrashType.SQL_INJECTION,
                severity=CrashSeverity.HIGH,
                description="Unknown Column Error"
            ),
            
            # XSS
            CrashPattern(
                pattern=r"<script[^>]*>.*GARLIC.*</script>",
                crash_type=CrashType.XSS,
                severity=CrashSeverity.MEDIUM,
                description="Reflected XSS"
            ),
            
            CrashPattern(
                pattern=r"javascript:.*GARLIC",
                crash_type=CrashType.XSS,
                severity=CrashSeverity.MEDIUM,
                description="JavaScript URL XSS"
            ),
            
            CrashPattern(
                pattern=r"on\w+\s*=\s*['\"].*GARLIC.*['\"]",
                crash_type=CrashType.XSS,
                severity=CrashSeverity.MEDIUM,
                description="Event Handler XSS"
            ),
            
            # File inclusion
            CrashPattern(
                pattern=r"fopen\(.*GARLIC.*\): failed to open stream",
                crash_type=CrashType.FILE_INCLUSION,
                severity=CrashSeverity.HIGH,
                description="File Inclusion Attempt"
            ),
            
            CrashPattern(
                pattern=r"include\(.*GARLIC.*\): failed to open stream",
                crash_type=CrashType.FILE_INCLUSION,
                severity=CrashSeverity.HIGH,
                description="Include Statement with Payload"
            ),
            
            CrashPattern(
                pattern=r"require\(.*GARLIC.*\): failed to open stream",
                crash_type=CrashType.FILE_INCLUSION,
                severity=CrashSeverity.HIGH,
                description="Require Statement with Payload"
            ),
            
            # Command injection
            CrashPattern(
                pattern=r"sh: .*GARLIC.*: command not found",
                crash_type=CrashType.COMMAND_INJECTION,
                severity=CrashSeverity.HIGH,
                description="Command Injection Attempt"
            ),
            
            CrashPattern(
                pattern=r"/bin/sh: .*GARLIC.*: not found",
                crash_type=CrashType.COMMAND_INJECTION,
                severity=CrashSeverity.HIGH,
                description="Shell Command Injection"
            ),
            
            # Memory errors
            CrashPattern(
                pattern=r"Allowed memory size of \d+ bytes exhausted",
                crash_type=CrashType.MEMORY_ERROR,
                severity=CrashSeverity.MEDIUM,
                description="Memory Exhaustion"
            ),
            
            CrashPattern(
                pattern=r"Segmentation fault",
                crash_type=CrashType.MEMORY_ERROR,
                severity=CrashSeverity.HIGH,
                description="Segmentation Fault"
            ),
            
            # Stack overflow
            CrashPattern(
                pattern=r"Maximum function nesting level of \d+ reached",
                crash_type=CrashType.STACK_OVERFLOW,
                severity=CrashSeverity.MEDIUM,
                description="Function Nesting Limit"
            ),
            
            # Division by zero
            CrashPattern(
                pattern=r"Division by zero",
                crash_type=CrashType.DIVISION_BY_ZERO,
                severity=CrashSeverity.LOW,
                description="Division by Zero"
            ),
            
            # Type errors
            CrashPattern(
                pattern=r"Call to undefined function.*GARLIC",
                crash_type=CrashType.TYPE_ERROR,
                severity=CrashSeverity.MEDIUM,
                description="Undefined Function Call"
            ),
            
            CrashPattern(
                pattern=r"Trying to get property of non-object.*GARLIC",
                crash_type=CrashType.TYPE_ERROR,
                severity=CrashSeverity.MEDIUM,
                description="Non-Object Property Access"
            ),
        ]
        
        return patterns
    
    def analyze_crash(self, payload: str, output: str, 
                     file_path: Optional[str] = None) -> Optional[CrashInfo]:
        """Analyze output for crash patterns."""
        start_time = time.time()
        
        try:
            # Check if output contains any crash patterns
            crash_info = None
            best_match = None
            best_confidence = 0.0
            
            for pattern in self.crash_patterns:
                match = pattern.regex.search(output)
                if match:
                    confidence = self._calculate_confidence(match, output, payload)
                    
                    if confidence > best_confidence:
                        best_confidence = confidence
                        best_match = (pattern, match)
            
            if best_match:
                pattern, match = best_match
                crash_info = self._create_crash_info(
                    pattern, match, payload, output, file_path, best_confidence
                )
                
                # Deduplicate crashes
                if not self._is_duplicate_crash(crash_info):
                    self._record_crash(crash_info)
                    return crash_info
            
            # Check for general error patterns
            if self._contains_error_patterns(output):
                crash_info = self._create_generic_crash_info(payload, output, file_path)
                if crash_info and not self._is_duplicate_crash(crash_info):
                    self._record_crash(crash_info)
                    return crash_info
            
            return None
            
        finally:
            analysis_time = time.time() - start_time
            self.analysis_times.append(analysis_time)
            # Keep only recent analysis times
            if len(self.analysis_times) > 1000:
                self.analysis_times = self.analysis_times[-1000:]
    
    def _calculate_confidence(self, match: re.Match, output: str, payload: str) -> float:
        """Calculate confidence score for a crash match."""
        confidence = 0.5  # Base confidence
        
        # Increase confidence if payload appears in the match
        if "GARLIC" in match.group(0):
            confidence += 0.3
        
        # Increase confidence based on match length (longer matches are more specific)
        match_length = len(match.group(0))
        if match_length > 50:
            confidence += 0.1
        elif match_length > 100:
            confidence += 0.2
        
        # Increase confidence if payload appears in the full output
        payload_appearances = output.count("GARLIC")
        if payload_appearances > 0:
            confidence += min(0.2, payload_appearances * 0.05)
        
        # Decrease confidence for common false positives
        false_positive_patterns = [
            r"wp-config\.php",
            r"wp-settings\.php",
            r"wp-load\.php",
            r"database connection",
            r"mysql_connect",
            r"mysqli_connect"
        ]
        
        for fp_pattern in false_positive_patterns:
            if re.search(fp_pattern, output, re.IGNORECASE):
                confidence -= 0.2
        
        return max(0.0, min(1.0, confidence))
    
    def _create_crash_info(self, pattern: CrashPattern, match: re.Match, 
                          payload: str, output: str, file_path: Optional[str],
                          confidence: float) -> CrashInfo:
        """Create CrashInfo object from pattern match."""
        # Extract additional information from match
        groups = match.groups()
        extracted_file = None
        extracted_line = None
        extracted_function = None
        
        if len(groups) >= 3:
            # Try to extract file and line information
            for i, group in enumerate(groups):
                if isinstance(group, str) and group.endswith('.php'):
                    extracted_file = group
                elif isinstance(group, str) and group.isdigit():
                    extracted_line = int(group)
        
        # Generate signature
        signature = self._generate_signature(pattern.crash_type, match.group(0), payload)
        
        # Determine exploitability
        exploitability = self._assess_exploitability(pattern, match, payload)
        
        # Map to CWE
        cwe_id = self._map_to_cwe(pattern.crash_type)
        
        return CrashInfo(
            signature=signature,
            crash_type=pattern.crash_type,
            severity=pattern.severity,
            payload=payload,
            output=output[:1000],  # Truncate long outputs
            stack_trace=self._extract_stack_trace(output),
            file_path=extracted_file or file_path,
            line_number=extracted_line,
            function_name=extracted_function,
            confidence=confidence,
            exploitability=exploitability,
            cwe_id=cwe_id,
            metadata={
                "pattern_description": pattern.description,
                "match_text": match.group(0),
                "full_output_length": len(output)
            }
        )
    
    def _create_generic_crash_info(self, payload: str, output: str, 
                                  file_path: Optional[str]) -> Optional[CrashInfo]:
        """Create generic crash info for unrecognized patterns."""
        # Look for general error indicators
        error_indicators = [
            r"Error:",
            r"Warning:",
            r"Notice:",
            r"Parse error:",
            r"Syntax error:",
            r"Exception:",
            r"Fatal:"
        ]
        
        for indicator in error_indicators:
            if re.search(indicator, output, re.IGNORECASE):
                signature = self._generate_signature(CrashType.UNKNOWN, output[:100], payload)
                
                return CrashInfo(
                    signature=signature,
                    crash_type=CrashType.UNKNOWN,
                    severity=CrashSeverity.LOW,
                    payload=payload,
                    output=output[:1000],
                    confidence=0.3,
                    exploitability="unknown",
                    metadata={"detected_by": "generic_error_detection"}
                )
        
        return None
    
    def _generate_signature(self, crash_type: CrashType, match_text: str, payload: str) -> str:
        """Generate a unique signature for the crash."""
        # Create a normalized signature
        normalized_match = re.sub(r'\d+', 'N', match_text)  # Replace numbers with N
        normalized_match = re.sub(r'[^\w\s]', 'X', normalized_match)  # Replace special chars
        
        signature_data = f"{crash_type.value}:{normalized_match}:{payload}"
        return hashlib.md5(signature_data.encode()).hexdigest()[:16]
    
    def _assess_exploitability(self, pattern: CrashPattern, match: re.Match, payload: str) -> str:
        """Assess the exploitability of a crash."""
        # High exploitability indicators
        high_indicators = [
            "sql injection",
            "command injection",
            "file inclusion",
            "xss"
        ]
        
        if any(indicator in pattern.description.lower() for indicator in high_indicators):
            return "high"
        
        # Medium exploitability indicators
        medium_indicators = [
            "fatal error",
            "undefined function",
            "non-object property"
        ]
        
        if any(indicator in pattern.description.lower() for indicator in medium_indicators):
            return "medium"
        
        # Check if payload appears in critical context
        match_text = match.group(0).lower()
        if "garlic" in match_text and any(keyword in match_text for keyword in 
            ["execute", "eval", "system", "shell", "command", "query", "sql"]):
            return "high"
        
        return "low"
    
    def _map_to_cwe(self, crash_type: CrashType) -> Optional[str]:
        """Map crash type to CWE ID."""
        cwe_mapping = {
            CrashType.SQL_INJECTION: "CWE-89",
            CrashType.XSS: "CWE-79",
            CrashType.FILE_INCLUSION: "CWE-22",
            CrashType.COMMAND_INJECTION: "CWE-78",
            CrashType.MEMORY_ERROR: "CWE-119",
            CrashType.STACK_OVERFLOW: "CWE-121",
            CrashType.DIVISION_BY_ZERO: "CWE-369",
            CrashType.TYPE_ERROR: "CWE-843"
        }
        
        return cwe_mapping.get(crash_type)
    
    def _extract_stack_trace(self, output: str) -> Optional[str]:
        """Extract stack trace from output."""
        stack_trace_pattern = r"Stack trace:.*?(?=\n\s*\n|\Z)"
        match = re.search(stack_trace_pattern, output, re.DOTALL)
        
        if match:
            return match.group(0).strip()
        
        return None
    
    def _contains_error_patterns(self, output: str) -> bool:
        """Check if output contains general error patterns."""
        error_patterns = [
            r"error",
            r"warning",
            r"notice",
            r"exception",
            r"fatal",
            r"parse error",
            r"syntax error"
        ]
        
        output_lower = output.lower()
        return any(re.search(pattern, output_lower) for pattern in error_patterns)
    
    def _is_duplicate_crash(self, crash_info: CrashInfo) -> bool:
        """Check if this crash is a duplicate of an existing one."""
        # Check exact signature match
        if crash_info.signature in self.crash_signatures:
            return True
        
        # Check similarity with existing crashes
        for existing_crash in self.crashes.values():
            similarity = self._calculate_crash_similarity(crash_info, existing_crash)
            if similarity >= self.similarity_threshold:
                return True
        
        return False
    
    def _calculate_crash_similarity(self, crash1: CrashInfo, crash2: CrashInfo) -> float:
        """Calculate similarity between two crashes."""
        similarity = 0.0
        
        # Same crash type
        if crash1.crash_type == crash2.crash_type:
            similarity += 0.3
        
        # Same severity
        if crash1.severity == crash2.severity:
            similarity += 0.2
        
        # Similar payloads
        if crash1.payload == crash2.payload:
            similarity += 0.3
        elif self._payload_similarity(crash1.payload, crash2.payload) > 0.8:
            similarity += 0.2
        
        # Similar outputs
        if crash1.output == crash2.output:
            similarity += 0.2
        elif self._output_similarity(crash1.output, crash2.output) > 0.8:
            similarity += 0.1
        
        return similarity
    
    def _payload_similarity(self, payload1: str, payload2: str) -> float:
        """Calculate similarity between two payloads."""
        if not payload1 or not payload2:
            return 0.0
        
        # Simple Jaccard similarity on character n-grams
        def get_ngrams(text, n=3):
            return set(text[i:i+n] for i in range(len(text)-n+1))
        
        ngrams1 = get_ngrams(payload1)
        ngrams2 = get_ngrams(payload2)
        
        intersection = len(ngrams1.intersection(ngrams2))
        union = len(ngrams1.union(ngrams2))
        
        return intersection / union if union > 0 else 0.0
    
    def _output_similarity(self, output1: str, output2: str) -> float:
        """Calculate similarity between two outputs."""
        if not output1 or not output2:
            return 0.0
        
        # Use simple word overlap
        words1 = set(output1.lower().split())
        words2 = set(output2.lower().split())
        
        intersection = len(words1.intersection(words2))
        union = len(words1.union(words2))
        
        return intersection / union if union > 0 else 0.0
    
    def _record_crash(self, crash_info: CrashInfo):
        """Record a new crash."""
        self.crashes[crash_info.signature] = crash_info
        self.crash_signatures.add(crash_info.signature)
        self.crash_stats[crash_info.crash_type.value] += 1
        
        # Add to cluster
        cluster_id = f"{crash_info.crash_type.value}_{crash_info.severity.value}"
        self.crash_clusters[cluster_id].append(crash_info.signature)
    
    def get_crash_summary(self) -> Dict[str, Any]:
        """Get summary of all crashes."""
        total_crashes = len(self.crashes)
        
        # Group by severity
        severity_counts = defaultdict(int)
        for crash in self.crashes.values():
            severity_counts[crash.severity.value] += 1
        
        # Group by type
        type_counts = defaultdict(int)
        for crash in self.crashes.values():
            type_counts[crash.crash_type.value] += 1
        
        # Group by exploitability
        exploitability_counts = defaultdict(int)
        for crash in self.crashes.values():
            exploitability_counts[crash.exploitability] += 1
        
        return {
            "total_crashes": total_crashes,
            "unique_crashes": len(self.crash_signatures),
            "severity_breakdown": dict(severity_counts),
            "type_breakdown": dict(type_counts),
            "exploitability_breakdown": dict(exploitability_counts),
            "average_analysis_time": sum(self.analysis_times) / len(self.analysis_times) if self.analysis_times else 0,
            "clusters": {k: len(v) for k, v in self.crash_clusters.items()}
        }
    
    def get_crash_table(self) -> Table:
        """Get Rich table with crash information."""
        table = Table(title="Crash Analysis Results")
        table.add_column("Type", style="cyan", width=15)
        table.add_column("Severity", style="red", width=10)
        table.add_column("Exploitability", style="yellow", width=12)
        table.add_column("Count", style="green", width=8)
        table.add_column("CWE", style="blue", width=8)
        
        # Group crashes by type and severity
        crash_groups = defaultdict(lambda: defaultdict(int))
        cwe_groups = defaultdict(set)
        
        for crash in self.crashes.values():
            key = f"{crash.crash_type.value}_{crash.severity.value}"
            crash_groups[key][crash.exploitability] += 1
            if crash.cwe_id:
                cwe_groups[key].add(crash.cwe_id)
        
        for key, exploitability_counts in crash_groups.items():
            crash_type, severity = key.split('_', 1)
            
            # Get most common exploitability
            most_common_exploitability = max(exploitability_counts.items(), key=lambda x: x[1])[0]
            total_count = sum(exploitability_counts.values())
            
            # Get CWE ID
            cwe_id = list(cwe_groups[key])[0] if cwe_groups[key] else "N/A"
            
            try:
                severity_enum = CrashSeverity(severity)
            except ValueError:
                severity_enum = CrashSeverity.LOW  # Default fallback
            
            severity_color = {
                CrashSeverity.LOW: "green",
                CrashSeverity.MEDIUM: "yellow",
                CrashSeverity.HIGH: "red1",
                CrashSeverity.CRITICAL: "bright_red"
            }.get(severity_enum, "white")
            
            table.add_row(
                crash_type,
                f"[{severity_color}]{severity.upper()}[/{severity_color}]",
                most_common_exploitability,
                str(total_count),
                cwe_id
            )
        
        return table
    
    def save_crash_report(self, output_file: str):
        """Save detailed crash report to file."""
        report = {
            "summary": self.get_crash_summary(),
            "crashes": {
                signature: {
                    "crash_type": crash.crash_type.value,
                    "severity": crash.severity.value,
                    "payload": crash.payload,
                    "output": crash.output,
                    "stack_trace": crash.stack_trace,
                    "timestamp": crash.timestamp,
                    "file_path": crash.file_path,
                    "line_number": crash.line_number,
                    "function_name": crash.function_name,
                    "confidence": crash.confidence,
                    "exploitability": crash.exploitability,
                    "cwe_id": crash.cwe_id,
                    "metadata": crash.metadata
                }
                for signature, crash in self.crashes.items()
            },
            "clusters": dict(self.crash_clusters),
            "analysis_stats": {
                "total_analysis_time": sum(self.analysis_times),
                "average_analysis_time": sum(self.analysis_times) / len(self.analysis_times) if self.analysis_times else 0,
                "total_analyses": len(self.analysis_times)
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        return output_file
