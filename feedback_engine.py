"""
Feedback-guided fuzzing engine inspired by AFL++ for WordPress plugin fuzzing.
Implements coverage tracking, mutation strategies, and input prioritization.
"""

import hashlib
import json
import os
import random
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from pathlib import Path

import numpy as np
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel


class MutationStrategy(Enum):
    """Different mutation strategies for fuzzing."""
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
class CoverageInfo:
    """Information about code coverage for a test case."""
    coverage_map: Dict[str, Set[int]] = field(default_factory=dict)
    total_coverage: int = 0
    unique_paths: Set[str] = field(default_factory=set)
    execution_time: float = 0.0
    memory_usage: int = 0


@dataclass
class TestCase:
    """Represents a test case with its coverage and metadata."""
    payload: Any
    coverage: CoverageInfo
    execution_count: int = 0
    last_executed: float = 0.0
    fitness_score: float = 0.0
    crash_info: Optional[Dict] = None
    parent_id: Optional[str] = None
    mutation_path: List[MutationStrategy] = field(default_factory=list)
    
    @property
    def id(self) -> str:
        """Generate unique ID for test case."""
        payload_str = str(self.payload)
        return hashlib.md5(payload_str.encode()).hexdigest()[:16]


@dataclass
class FuzzingStats:
    """Statistics about the fuzzing process."""
    total_executions: int = 0
    total_coverage: int = 0
    crashes_found: int = 0
    unique_crashes: int = 0
    start_time: float = field(default_factory=time.time)
    last_crash_time: float = 0.0
    executions_per_second: float = 0.0
    coverage_growth_rate: float = 0.0
    
    @property
    def uptime(self) -> float:
        return time.time() - self.start_time


class FeedbackEngine:
    """Main feedback-guided fuzzing engine."""
    
    def __init__(self, console: Console, config: Dict[str, Any] = None):
        self.console = console
        self.config = config or self._default_config()
        
        # Core data structures
        self.test_cases: Dict[str, TestCase] = {}
        self.input_queue: deque = deque()
        self.coverage_map: Dict[str, Set[int]] = defaultdict(set)
        self.crash_signatures: Set[str] = set()
        self.mutation_strategies = list(MutationStrategy)
        
        # Statistics
        self.stats = FuzzingStats()
        self.last_stats_update = time.time()
        
        # Performance tracking
        self.execution_times: deque = deque(maxlen=100)
        self.coverage_history: deque = deque(maxlen=1000)
        
        # Dictionary for mutation strategies
        self.dictionary: Set[str] = self._load_dictionary()
        
        # Interesting values for mutation
        self.interesting_values = [
            -1, 0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128,
            255, 256, 32767, 32768, 65535, 65536, 2147483647, 2147483648
        ]
        
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration for the fuzzing engine."""
        return {
            "max_executions": 100000,
            "max_test_cases": 10000,
            "coverage_threshold": 0.01,
            "mutation_probability": 0.5,
            "splice_probability": 0.1,
            "havoc_probability": 0.3,
            "dictionary_probability": 0.2,
            "timeout": 30,
            "memory_limit": 512 * 1024 * 1024,  # 512MB
            "crash_dedup_threshold": 0.8,
            "fitness_weights": {
                "coverage": 0.4,
                "uniqueness": 0.3,
                "execution_time": 0.1,
                "crash_potential": 0.2
            }
        }
    
    def _load_dictionary(self) -> Set[str]:
        """Load mutation dictionary from various sources."""
        dictionary = set()
        
        # Load from existing payloads
        try:
            with open("docker_image/magic_payloads.php", "r") as f:
                content = f.read()
                # Extract payloads from the PHP file
                import re
                payloads = re.findall(r'"([^"]*GARLIC[^"]*)"', content)
                dictionary.update(payloads)
        except FileNotFoundError:
            pass
            
        # Common WordPress patterns
        wordpress_patterns = [
            "wp_ajax_", "wp_ajax_nopriv_", "admin_init", "init",
            "wp_enqueue_script", "wp_enqueue_style", "add_action",
            "add_filter", "wp_head", "wp_footer", "the_content",
            "wp_insert_post", "wp_update_post", "wp_delete_post",
            "get_posts", "wp_query", "get_user_meta", "update_user_meta"
        ]
        dictionary.update(wordpress_patterns)
        
        # Common vulnerability patterns
        vuln_patterns = [
            "../", "../../", "../../../", "..\\", "..\\..\\",
            "<script>", "</script>", "javascript:", "vbscript:",
            "onload=", "onerror=", "onclick=", "onmouseover=",
            "union select", "drop table", "insert into", "delete from",
            "exec(", "system(", "shell_exec(", "passthru("
        ]
        dictionary.update(vuln_patterns)
        
        return dictionary
    
    def add_test_case(self, payload: Any, coverage: CoverageInfo, 
                     parent_id: Optional[str] = None, 
                     mutation_strategy: Optional[MutationStrategy] = None) -> str:
        """Add a new test case to the queue."""
        test_case = TestCase(
            payload=payload,
            coverage=coverage,
            parent_id=parent_id,
            mutation_path=[mutation_strategy] if mutation_strategy else []
        )
        
        # Calculate fitness score
        test_case.fitness_score = self._calculate_fitness(test_case)
        
        # Add to test cases
        test_id = test_case.id
        self.test_cases[test_id] = test_case
        
        # Add to priority queue based on fitness
        self._add_to_queue(test_case)
        
        # Update coverage map
        self._update_coverage_map(coverage)
        
        return test_id
    
    def _calculate_fitness(self, test_case: TestCase) -> float:
        """Calculate fitness score for a test case."""
        weights = self.config.get("fitness_weights", {
            "coverage": 0.4,
            "uniqueness": 0.3,
            "execution_time": 0.1,
            "crash_potential": 0.2
        })
        
        # Coverage component
        coverage_score = len(test_case.coverage.unique_paths) / max(1, self.stats.total_coverage)
        
        # Uniqueness component
        uniqueness_score = 1.0 if test_case.id not in self.test_cases else 0.0
        
        # Execution time component (prefer faster executions)
        time_score = 1.0 / max(1.0, test_case.coverage.execution_time)
        
        # Crash potential component
        crash_score = 1.0 if test_case.crash_info else 0.0
        
        fitness = (
            weights["coverage"] * coverage_score +
            weights["uniqueness"] * uniqueness_score +
            weights["execution_time"] * time_score +
            weights["crash_potential"] * crash_score
        )
        
        return fitness
    
    def _add_to_queue(self, test_case: TestCase):
        """Add test case to priority queue."""
        # Insert in fitness order (highest first)
        inserted = False
        for i, (_, existing_id) in enumerate(self.input_queue):
            if self.test_cases[existing_id].fitness_score < test_case.fitness_score:
                self.input_queue.insert(i, (test_case.fitness_score, test_case.id))
                inserted = True
                break
        
        if not inserted:
            self.input_queue.append((test_case.fitness_score, test_case.id))
    
    def _update_coverage_map(self, coverage: CoverageInfo):
        """Update global coverage map."""
        for file_path, lines in coverage.coverage_map.items():
            self.coverage_map[file_path].update(lines)
        
        # Update total coverage
        self.stats.total_coverage = sum(len(lines) for lines in self.coverage_map.values())
    
    def get_next_test_case(self) -> Optional[TestCase]:
        """Get the next test case to execute."""
        if not self.input_queue:
            return None
            
        _, test_id = self.input_queue.popleft()
        return self.test_cases.get(test_id)
    
    def mutate_test_case(self, test_case: TestCase) -> List[TestCase]:
        """Generate mutations of a test case."""
        mutations = []
        
        # Choose mutation strategy
        weights = [
            self.config.get("mutation_probability", 0.5),
            self.config.get("mutation_probability", 0.5),
            self.config.get("dictionary_probability", 0.2),
            self.config.get("havoc_probability", 0.3),
            self.config.get("splice_probability", 0.1),
            self.config.get("mutation_probability", 0.5)
        ]
        
        strategy = random.choices(self.mutation_strategies, weights=weights)[0]
        
        # Generate mutations based on strategy
        if strategy == MutationStrategy.BIT_FLIP:
            mutations.extend(self._bit_flip_mutations(test_case))
        elif strategy == MutationStrategy.ARITHMETIC:
            mutations.extend(self._arithmetic_mutations(test_case))
        elif strategy == MutationStrategy.DICTIONARY:
            mutations.extend(self._dictionary_mutations(test_case))
        elif strategy == MutationStrategy.HAVOC:
            mutations.extend(self._havoc_mutations(test_case))
        elif strategy == MutationStrategy.SPLICE:
            mutations.extend(self._splice_mutations(test_case))
        elif strategy == MutationStrategy.INTERESTING:
            mutations.extend(self._interesting_mutations(test_case))
        
        return mutations
    
    def _bit_flip_mutations(self, test_case: TestCase) -> List[TestCase]:
        """Generate bit-flip mutations."""
        mutations = []
        payload = test_case.payload
        
        if isinstance(payload, str):
            # Random bit flips in string
            for _ in range(random.randint(1, 5)):
                if len(payload) > 0:
                    pos = random.randint(0, len(payload) - 1)
                    new_payload = payload[:pos] + chr(ord(payload[pos]) ^ (1 << random.randint(0, 7))) + payload[pos+1:]
                    
                    # Create new coverage info (will be filled by execution)
                    new_coverage = CoverageInfo()
                    new_test_case = TestCase(
                        payload=new_payload,
                        coverage=new_coverage,
                        parent_id=test_case.id,
                        mutation_path=test_case.mutation_path + [MutationStrategy.BIT_FLIP]
                    )
                    mutations.append(new_test_case)
        
        return mutations
    
    def _arithmetic_mutations(self, test_case: TestCase) -> List[TestCase]:
        """Generate arithmetic mutations."""
        mutations = []
        payload = test_case.payload
        
        if isinstance(payload, (int, float)):
            for value in self.interesting_values:
                new_payload = payload + value
                new_coverage = CoverageInfo()
                new_test_case = TestCase(
                    payload=new_payload,
                    coverage=new_coverage,
                    parent_id=test_case.id,
                    mutation_path=test_case.mutation_path + [MutationStrategy.ARITHMETIC]
                )
                mutations.append(new_test_case)
        
        return mutations
    
    def _dictionary_mutations(self, test_case: TestCase) -> List[TestCase]:
        """Generate dictionary-based mutations."""
        mutations = []
        payload = test_case.payload
        
        if isinstance(payload, str):
            for word in random.sample(list(self.dictionary), min(3, len(self.dictionary))):
                # Insert, append, or replace
                mutation_type = random.choice(["insert", "append", "replace"])
                
                if mutation_type == "insert" and len(payload) > 0:
                    pos = random.randint(0, len(payload))
                    new_payload = payload[:pos] + word + payload[pos:]
                elif mutation_type == "append":
                    new_payload = payload + word
                elif mutation_type == "replace" and len(payload) > 0:
                    pos = random.randint(0, len(payload) - 1)
                    new_payload = payload[:pos] + word + payload[pos+1:]
                else:
                    continue
                
                new_coverage = CoverageInfo()
                new_test_case = TestCase(
                    payload=new_payload,
                    coverage=new_coverage,
                    parent_id=test_case.id,
                    mutation_path=test_case.mutation_path + [MutationStrategy.DICTIONARY]
                )
                mutations.append(new_test_case)
        
        return mutations
    
    def _havoc_mutations(self, test_case: TestCase) -> List[TestCase]:
        """Generate havoc mutations (random combinations)."""
        mutations = []
        payload = test_case.payload
        
        if isinstance(payload, str):
            for _ in range(random.randint(1, 3)):
                new_payload = payload
                
                # Apply random transformations
                for _ in range(random.randint(1, 5)):
                    transform = random.choice([
                        "delete_char", "duplicate_char", "swap_chars", 
                        "random_insert", "case_flip"
                    ])
                    
                    if transform == "delete_char" and len(new_payload) > 0:
                        pos = random.randint(0, len(new_payload) - 1)
                        new_payload = new_payload[:pos] + new_payload[pos+1:]
                    elif transform == "duplicate_char" and len(new_payload) > 0:
                        pos = random.randint(0, len(new_payload) - 1)
                        new_payload = new_payload[:pos] + new_payload[pos] + new_payload[pos:]
                    elif transform == "swap_chars" and len(new_payload) > 1:
                        pos1, pos2 = random.sample(range(len(new_payload)), 2)
                        chars = list(new_payload)
                        chars[pos1], chars[pos2] = chars[pos2], chars[pos1]
                        new_payload = ''.join(chars)
                    elif transform == "random_insert":
                        pos = random.randint(0, len(new_payload))
                        char = chr(random.randint(32, 126))
                        new_payload = new_payload[:pos] + char + new_payload[pos:]
                    elif transform == "case_flip" and len(new_payload) > 0:
                        pos = random.randint(0, len(new_payload) - 1)
                        char = new_payload[pos]
                        if char.isupper():
                            new_char = char.lower()
                        elif char.islower():
                            new_char = char.upper()
                        else:
                            continue
                        new_payload = new_payload[:pos] + new_char + new_payload[pos+1:]
                
                new_coverage = CoverageInfo()
                new_test_case = TestCase(
                    payload=new_payload,
                    coverage=new_coverage,
                    parent_id=test_case.id,
                    mutation_path=test_case.mutation_path + [MutationStrategy.HAVOC]
                )
                mutations.append(new_test_case)
        
        return mutations
    
    def _splice_mutations(self, test_case: TestCase) -> List[TestCase]:
        """Generate splice mutations by combining with other test cases."""
        mutations = []
        
        if len(self.test_cases) < 2:
            return mutations
        
        # Get another random test case
        other_test_id = random.choice(list(self.test_cases.keys()))
        if other_test_id == test_case.id:
            return mutations
        
        other_test = self.test_cases[other_test_id]
        
        # Combine payloads
        if isinstance(test_case.payload, str) and isinstance(other_test.payload, str):
            # Simple concatenation for now
            new_payload = test_case.payload + other_test.payload
            
            new_coverage = CoverageInfo()
            new_test_case = TestCase(
                payload=new_payload,
                coverage=new_coverage,
                parent_id=test_case.id,
                mutation_path=test_case.mutation_path + [MutationStrategy.SPLICE]
            )
            mutations.append(new_test_case)
        
        return mutations
    
    def _interesting_mutations(self, test_case: TestCase) -> List[TestCase]:
        """Generate mutations using interesting values."""
        mutations = []
        payload = test_case.payload
        
        if isinstance(payload, str):
            for value in self.interesting_values:
                new_payload = str(value)
                
                new_coverage = CoverageInfo()
                new_test_case = TestCase(
                    payload=new_payload,
                    coverage=new_coverage,
                    parent_id=test_case.id,
                    mutation_path=test_case.mutation_path + [MutationStrategy.INTERESTING]
                )
                mutations.append(new_test_case)
        
        return mutations
    
    def analyze_crash(self, test_case: TestCase, crash_output: str) -> Optional[Dict]:
        """Analyze a crash and determine its severity."""
        crash_signature = hashlib.md5(crash_output.encode()).hexdigest()
        
        if crash_signature in self.crash_signatures:
            return None  # Duplicate crash
        
        self.crash_signatures.add(crash_signature)
        
        # Analyze crash severity based on patterns
        severity = CrashSeverity.LOW
        crash_type = "unknown"
        
        if "fatal error" in crash_output.lower():
            severity = CrashSeverity.HIGH
            crash_type = "fatal_error"
        elif "sql syntax" in crash_output.lower():
            severity = CrashSeverity.MEDIUM
            crash_type = "sql_injection"
        elif "xss" in crash_output.lower() or "<script>" in crash_output:
            severity = CrashSeverity.MEDIUM
            crash_type = "xss"
        elif "file inclusion" in crash_output.lower() or "include" in crash_output.lower():
            severity = CrashSeverity.HIGH
            crash_type = "file_inclusion"
        
        crash_info = {
            "signature": crash_signature,
            "severity": severity,
            "type": crash_type,
            "output": crash_output,
            "timestamp": time.time()
        }
        
        test_case.crash_info = crash_info
        self.stats.crashes_found += 1
        self.stats.unique_crashes += 1
        self.stats.last_crash_time = time.time()
        
        return crash_info
    
    def update_stats(self):
        """Update fuzzing statistics."""
        current_time = time.time()
        time_diff = current_time - self.last_stats_update
        
        if time_diff > 0:
            self.stats.executions_per_second = len(self.execution_times) / time_diff
            self.stats.coverage_growth_rate = len(self.coverage_history) / time_diff
        
        self.last_stats_update = current_time
    
    def get_stats_table(self) -> Table:
        """Get a Rich table with current statistics."""
        table = Table(title="Fuzzing Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Executions", str(self.stats.total_executions))
        table.add_row("Total Coverage", str(self.stats.total_coverage))
        table.add_row("Crashes Found", str(self.stats.crashes_found))
        table.add_row("Unique Crashes", str(self.stats.unique_crashes))
        table.add_row("Executions/sec", f"{self.stats.executions_per_second:.2f}")
        table.add_row("Uptime", f"{self.stats.uptime:.1f}s")
        table.add_row("Queue Size", str(len(self.input_queue)))
        table.add_row("Test Cases", str(len(self.test_cases)))
        
        return table
    
    def save_state(self, filepath: str):
        """Save fuzzing state to file."""
        state = {
            "test_cases": {k: {
                "payload": v.payload,
                "coverage": {
                    "coverage_map": dict(v.coverage.coverage_map),
                    "total_coverage": v.coverage.total_coverage,
                    "unique_paths": list(v.coverage.unique_paths),
                    "execution_time": v.coverage.execution_time,
                    "memory_usage": v.coverage.memory_usage
                },
                "execution_count": v.execution_count,
                "last_executed": v.last_executed,
                "fitness_score": v.fitness_score,
                "crash_info": v.crash_info,
                "parent_id": v.parent_id,
                "mutation_path": [s.value for s in v.mutation_path]
            } for k, v in self.test_cases.items()},
            "coverage_map": dict(self.coverage_map),
            "crash_signatures": list(self.crash_signatures),
            "stats": {
                "total_executions": self.stats.total_executions,
                "total_coverage": self.stats.total_coverage,
                "crashes_found": self.stats.crashes_found,
                "unique_crashes": self.stats.unique_crashes,
                "start_time": self.stats.start_time,
                "last_crash_time": self.stats.last_crash_time
            }
        }
        
        with open(filepath, "w") as f:
            json.dump(state, f, indent=2)
    
    def load_state(self, filepath: str):
        """Load fuzzing state from file."""
        with open(filepath, "r") as f:
            state = json.load(f)
        
        # Reconstruct test cases
        self.test_cases = {}
        for k, v in state["test_cases"].items():
            coverage = CoverageInfo(
                coverage_map={k: set(v) for k, v in v["coverage"]["coverage_map"].items()},
                total_coverage=v["coverage"]["total_coverage"],
                unique_paths=set(v["coverage"]["unique_paths"]),
                execution_time=v["coverage"]["execution_time"],
                memory_usage=v["coverage"]["memory_usage"]
            )
            
            test_case = TestCase(
                payload=v["payload"],
                coverage=coverage,
                execution_count=v["execution_count"],
                last_executed=v["last_executed"],
                fitness_score=v["fitness_score"],
                crash_info=v["crash_info"],
                parent_id=v["parent_id"],
                mutation_path=[MutationStrategy(s) for s in v["mutation_path"]]
            )
            self.test_cases[k] = test_case
        
        # Reconstruct other state
        self.coverage_map = {k: set(v) for k, v in state["coverage_map"].items()}
        self.crash_signatures = set(state["crash_signatures"])
        
        # Reconstruct stats
        stats_data = state["stats"]
        self.stats = FuzzingStats(
            total_executions=stats_data["total_executions"],
            total_coverage=stats_data["total_coverage"],
            crashes_found=stats_data["crashes_found"],
            unique_crashes=stats_data["unique_crashes"],
            start_time=stats_data["start_time"],
            last_crash_time=stats_data["last_crash_time"]
        )
        
        # Reconstruct queue
        self.input_queue = deque()
        for test_case in self.test_cases.values():
            self._add_to_queue(test_case)
