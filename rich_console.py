"""
Enhanced Rich-based console UI for wpgarlic fuzzing tool.
Provides real-time visualization with progress bars, statistics, and modern UI.
"""

import time
from typing import Any, Dict, List, Optional, Callable
from datetime import datetime, timedelta

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, 
    TimeElapsedColumn, TimeRemainingColumn, MofNCompleteColumn,
    ProgressColumn, TaskID, Task
)
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich.status import Status
from rich.syntax import Syntax
from rich.tree import Tree
from rich import box
from rich.spinner import Spinner
from rich.rule import Rule
from rich.markup import escape
from rich.measure import Measurement
from rich.segment import Segment

from feedback_engine import FeedbackEngine, FuzzingStats, TestCase, CrashSeverity


class ExecutionsPerSecondColumn(ProgressColumn):
    """Custom column to show executions per second."""
    
    def render(self, task: Task) -> Text:
        if task.total and task.completed > 0:
            elapsed = task.time_elapsed or 0
            if elapsed > 0:
                rate = task.completed / elapsed
                return Text(f"{rate:.1f}/s", style="progress.data.speed")
        return Text("?/s", style="progress.data.speed")


class FuzzingConsole:
    """Enhanced Rich-based console interface for fuzzing operations."""
    
    def __init__(self, feedback_engine: FeedbackEngine):
        self.feedback_engine = feedback_engine
        # Configure console for Windows compatibility
        self.console = Console(force_terminal=True, legacy_windows=False)
        self.start_time = time.time()
        
        # UI state
        self.current_plugin = "Unknown"
        self.current_endpoint = "Unknown"
        self.last_update = time.time()
        self.update_interval = 0.5  # Update UI every 500ms for smoother experience
        
        # Enhanced progress tracking with multiple progress bars
        self.progress = Progress(
            SpinnerColumn(spinner_name="dots12"),
            TextColumn("[bold blue]{task.description}", justify="left"),
            BarColumn(bar_width=40),
            "[progress.percentage]{task.percentage:>3.0f}%",
            "•",
            MofNCompleteColumn(),
            "•",
            TimeElapsedColumn(),
            "•",
            ExecutionsPerSecondColumn(),
            console=self.console,
            expand=True
        )
        
        # Task IDs for different progress bars
        self.main_task = None
        self.coverage_task = None
        self.crash_task = None
        
        # Status tracking
        self.status = Status("Initializing fuzzer...", spinner="dots12")
        
        # Live UI components
        self.live = None
        self.layout = None
        self.is_live_mode = False
        
    def start_fuzzing_session(self, plugin_name: str, endpoint: str = None, max_executions: int = 100000):
        """Start a new fuzzing session with enhanced progress tracking."""
        self.current_plugin = plugin_name
        self.current_endpoint = endpoint or "All endpoints"
        self.start_time = time.time()
        
        self.console.clear()
        
        # Create welcome banner
        banner = Panel.fit(
            f"[bold blue]🧄 wpgarlic[/bold blue] - Enhanced WordPress Plugin Fuzzer\n"
            f"[green]🎯 Plugin:[/green] {plugin_name}\n"
            f"[green]🔗 Endpoint:[/green] {self.current_endpoint}\n"
            f"[green]⏰ Started:[/green] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"[green]🎯 Target:[/green] {max_executions:,} executions",
            title="🚀 Fuzzing Session",
            border_style="blue",
            padding=(1, 2)
        )
        
        self.console.print(banner)
        self.console.print()
        
        # Initialize progress tasks
        with self.progress:
            self.main_task = self.progress.add_task(
                f"Fuzzing {plugin_name}",
                total=max_executions,
                completed=0
            )
            
            self.coverage_task = self.progress.add_task(
                "Code Coverage Discovery",
                total=1000,  # Will be updated dynamically
                completed=0
            )
            
            self.crash_task = self.progress.add_task(
                "Crash Detection",
                total=100,  # Will be updated dynamically
                completed=0
            )
    
    def update_progress(self, executions: int, max_executions: int, 
                       coverage_lines: int, crashes_found: int):
        """Update progress bars with current statistics."""
        if not self.is_live_mode:
            with self.progress:
                if self.main_task:
                    self.progress.update(
                        self.main_task,
                        completed=executions,
                        total=max_executions,
                        description=f"Fuzzing {self.current_plugin}"
                    )
                
                if self.coverage_task:
                    # Update coverage task with dynamic total
                    if coverage_lines > self.progress.tasks[self.coverage_task].total:
                        self.progress.update(self.coverage_task, total=coverage_lines * 2)
                    self.progress.update(
                        self.coverage_task,
                        completed=coverage_lines,
                        description="Code Coverage Discovery"
                    )
                
                if self.crash_task:
                    # Update crash task
                    if crashes_found > self.progress.tasks[self.crash_task].total:
                        self.progress.update(self.crash_task, total=crashes_found * 2)
                    self.progress.update(
                        self.crash_task,
                        completed=crashes_found,
                        description="Crash Detection"
                    )
    
    def start_live_interface(self, update_callback: Callable = None):
        """Start the enhanced live updating interface."""
        self.is_live_mode = True
        self.layout = self.create_enhanced_layout()
        
        with Live(self.layout, console=self.console, refresh_per_second=4) as live:
            self.live = live
            while True:
                try:
                    self.update_live_interface()
                    
                    if update_callback:
                        update_callback()
                    
                    time.sleep(self.update_interval)
                    
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    self.console.print(f"[red]Error updating UI: {e}[/red]")
                    time.sleep(1)
    
    def stop_live_interface(self):
        """Stop the live interface."""
        self.is_live_mode = False
        if self.live:
            self.live.stop()
        
    def create_enhanced_layout(self) -> Layout:
        """Create an enhanced layout for the fuzzing interface."""
        layout = Layout()
        
        # Main structure
        layout.split_column(
            Layout(name="header", size=4),
            Layout(name="progress_section", size=8),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3)
        )
        
        # Main content split
        layout["main"].split_row(
            Layout(name="left", ratio=1),
            Layout(name="right", ratio=1)
        )
        
        # Left column: Statistics and coverage
        layout["left"].split_column(
            Layout(name="stats", size=12),
            Layout(name="coverage", size=10),
            Layout(name="crashes", ratio=1)
        )
        
        # Right column: Current test and findings
        layout["right"].split_column(
            Layout(name="current_test", size=8),
            Layout(name="recent_findings", size=8),
            Layout(name="mutation_stats", ratio=1)
        )
        
        return layout
    
    def update_live_interface(self):
        """Update all panels in the live interface."""
        if not self.layout:
            return
            
        # Update header
        self.layout["header"].update(self.create_header_panel())
        
        # Update progress section
        self.layout["progress_section"].update(self.create_progress_section())
        
        # Update main panels
        self.layout["stats"].update(self.create_stats_panel())
        self.layout["coverage"].update(self.create_coverage_panel())
        self.layout["crashes"].update(self.create_crashes_panel())
        self.layout["current_test"].update(self.create_current_test_panel())
        self.layout["recent_findings"].update(self.create_recent_findings_panel())
        self.layout["mutation_stats"].update(self.create_mutation_stats_panel())
        self.layout["footer"].update(self.create_footer_panel())
    
    def create_header_panel(self) -> Panel:
        """Create the header panel with session info."""
        uptime = time.time() - self.start_time
        uptime_str = str(timedelta(seconds=int(uptime)))
        
        header_text = Text()
        header_text.append("🧄 ", style="blue")
        header_text.append("wpgarlic", style="bold blue")
        header_text.append(" | ", style="dim")
        header_text.append("🎯 ", style="green")
        header_text.append(self.current_plugin, style="bold green")
        header_text.append(" | ", style="dim")
        header_text.append("🔗 ", style="cyan")
        header_text.append(self.current_endpoint, style="cyan")
        header_text.append(" | ", style="dim")
        header_text.append("⏰ ", style="yellow")
        header_text.append(uptime_str, style="bold yellow")
        
        return Panel(
            Align.center(header_text),
            box=box.ROUNDED,
            border_style="blue"
        )
    
    def create_progress_section(self) -> Panel:
        """Create the progress section with enhanced progress bars."""
        stats = self.feedback_engine.stats if self.feedback_engine else None
        
        if not stats:
            return Panel("Initializing...", title="Progress", border_style="dim")
        
        # Create a custom progress display
        progress_text = Text()
        
        # Main progress
        max_executions = getattr(self.feedback_engine, 'config', {}).get('max_executions', 100000)
        main_progress = min(100, (stats.total_executions / max_executions) * 100)
        
        progress_text.append("🎯 Overall Progress\n", style="bold blue")
        progress_text.append(f"Executions: {stats.total_executions:,} / {max_executions:,} ")
        progress_text.append(f"({main_progress:.1f}%)\n", style="green")
        
        # Create a visual progress bar
        bar_length = 40
        filled = int((main_progress / 100) * bar_length)
        bar = "█" * filled + "░" * (bar_length - filled)
        progress_text.append(f"[{bar}]\n", style="green")
        
        # Execution rate
        if stats.executions_per_second > 0:
            progress_text.append(f"🚀 Speed: {stats.executions_per_second:.1f} exec/sec\n", style="cyan")
        
        # Coverage progress
        coverage_progress = min(100, (stats.total_coverage / 10000) * 100)  # Assume 10k lines as baseline
        progress_text.append(f"📊 Coverage: {stats.total_coverage:,} lines ({coverage_progress:.1f}%)\n", style="blue")
        
        # Crash progress
        if stats.crashes_found > 0:
            progress_text.append(f"💥 Crashes: {stats.crashes_found:,} found", style="red")
        
        return Panel(progress_text, title="📈 Progress", border_style="blue")
    
    def update_header(self) -> Panel:
        """Update the header panel."""
        uptime = time.time() - self.start_time
        uptime_str = str(timedelta(seconds=int(uptime)))
        
        return Panel(
            f"[bold blue]wpgarlic[/bold blue] | "
            f"Plugin: [green]{self.current_plugin}[/green] | "
            f"Endpoint: [green]{self.current_endpoint}[/green] | "
            f"Uptime: [yellow]{uptime_str}[/yellow]",
            box=box.ROUNDED
        )
    
    def create_stats_panel(self) -> Panel:
        """Create an enhanced statistics panel."""
        stats = self.feedback_engine.stats if self.feedback_engine else None
        
        if not stats:
            return Panel("No statistics available", title="📊 Statistics", border_style="dim")
        
        table = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
        table.add_column("Metric", style="cyan bold", width=18)
        table.add_column("Value", style="green", justify="right", width=12)
        
        # Core statistics with emojis
        table.add_row("🎯 Executions", f"{stats.total_executions:,}")
        table.add_row("⚡ Speed", f"{stats.executions_per_second:.1f}/s")
        table.add_row("📊 Coverage", f"{stats.total_coverage:,}")
        table.add_row("💥 Crashes", f"{stats.crashes_found:,}")
        table.add_row("🔍 Unique", f"{stats.unique_crashes:,}")
        
        if hasattr(self.feedback_engine, 'input_queue'):
            table.add_row("📋 Queue", f"{len(self.feedback_engine.input_queue):,}")
        if hasattr(self.feedback_engine, 'test_cases'):
            table.add_row("🧪 Test Cases", f"{len(self.feedback_engine.test_cases):,}")
        
        return Panel(table, title="📊 Statistics", border_style="blue")
    
    def create_coverage_panel(self) -> Panel:
        """Create an enhanced coverage panel."""
        if not self.feedback_engine or not hasattr(self.feedback_engine, 'coverage_map'):
            return Panel("No coverage data available", title="📊 Code Coverage", border_style="yellow")
        
        coverage_map = self.feedback_engine.coverage_map
        
        if not coverage_map:
            return Panel("No coverage data available", title="📊 Code Coverage", border_style="yellow")
        
        # Create coverage summary
        total_lines = sum(len(lines) for lines in coverage_map.values())
        total_files = len(coverage_map)
        
        coverage_text = Text()
        coverage_text.append(f"📁 Files: {total_files:,}\n", style="cyan")
        coverage_text.append(f"📝 Lines: {total_lines:,}\n", style="green")
        
        # Show top 5 files with most coverage
        sorted_files = sorted(coverage_map.items(), key=lambda x: len(x[1]), reverse=True)
        
        coverage_text.append("\nTop Files:\n", style="bold")
        for i, (file_path, lines) in enumerate(sorted_files[:5]):
            file_name = file_path.split("/")[-1]
            coverage_percent = len(lines) / max(1, total_lines) * 100
            coverage_text.append(f"  {i+1}. {file_name}\n", style="white")
            coverage_text.append(f"     {len(lines)} lines ({coverage_percent:.1f}%)\n", style="dim")
        
        if len(sorted_files) > 5:
            coverage_text.append(f"  ... and {len(sorted_files) - 5} more files\n", style="dim")
        
        return Panel(coverage_text, title="📊 Code Coverage", border_style="green")
    
    def create_crashes_panel(self) -> Panel:
        """Create an enhanced crashes panel."""
        if not self.feedback_engine or not hasattr(self.feedback_engine, 'test_cases'):
            return Panel("No crash data available", title="💥 Crashes", border_style="green")
        
        crashes = []
        
        # Collect recent crashes
        for test_case in self.feedback_engine.test_cases.values():
            if hasattr(test_case, 'crash_info') and test_case.crash_info:
                crashes.append(test_case.crash_info)
        
        if not crashes:
            return Panel("✅ No crashes found", title="💥 Crashes", border_style="green")
        
        # Sort by timestamp (newest first)
        crashes.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        
        crash_text = Text()
        crash_text.append(f"Total Crashes: {len(crashes):,}\n", style="red bold")
        
        # Show top 3 crashes
        for i, crash in enumerate(crashes[:3]):
            severity = crash.get("severity", "unknown")
            crash_type = crash.get("type", "unknown")
            timestamp = crash.get("timestamp", 0)
            
            if timestamp:
                time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")
            else:
                time_str = "Unknown"
            
            severity_color = {
                CrashSeverity.LOW: "yellow",
                CrashSeverity.MEDIUM: "orange1",
                CrashSeverity.HIGH: "red1",
                CrashSeverity.CRITICAL: "bright_red"
            }.get(severity, "white")
            
            crash_text.append(f"{i+1}. {crash_type}\n", style="white bold")
            crash_text.append(f"   Severity: ", style="dim")
            crash_text.append(f"{severity.value.upper()}\n", style=severity_color)
            crash_text.append(f"   Time: {time_str}\n", style="dim")
            
            if i < 2:  # Add separator except for last item
                crash_text.append("\n", style="dim")
        
        if len(crashes) > 3:
            crash_text.append(f"\n... and {len(crashes) - 3} more crashes", style="dim")
        
        return Panel(crash_text, title="💥 Crashes", border_style="red")
    
    def create_mutation_stats_panel(self) -> Panel:
        """Create a mutation statistics panel."""
        if not self.feedback_engine:
            return Panel("No mutation data available", title="🧬 Mutations", border_style="dim")
        
        mutation_text = Text()
        mutation_text.append("Mutation Statistics\n", style="bold")
        
        # Get mutation strategy counts if available
        if hasattr(self.feedback_engine, 'mutation_counts'):
            counts = self.feedback_engine.mutation_counts
            total_mutations = sum(counts.values())
            
            if total_mutations > 0:
                mutation_text.append(f"Total Mutations: {total_mutations:,}\n", style="cyan")
                
                # Show top mutation strategies
                sorted_strategies = sorted(counts.items(), key=lambda x: x[1], reverse=True)
                for strategy, count in sorted_strategies[:5]:
                    percentage = (count / total_mutations) * 100
                    mutation_text.append(f"{strategy}: {count:,} ({percentage:.1f}%)\n", style="white")
            else:
                mutation_text.append("No mutations performed yet\n", style="dim")
        else:
            mutation_text.append("Mutation tracking not available\n", style="dim")
        
        # Add current mutation info if available
        if hasattr(self.feedback_engine, 'current_mutation'):
            current = self.feedback_engine.current_mutation
            mutation_text.append(f"\nCurrent: {current}\n", style="green")
        
        return Panel(mutation_text, title="🧬 Mutations", border_style="magenta")
    
    def update_progress_panel(self, current_test: Optional[TestCase] = None) -> Panel:
        """Update the progress panel."""
        stats = self.feedback_engine.stats
        
        # Calculate progress percentage
        max_executions = self.feedback_engine.config.get("max_executions", 100000)
        progress_percent = min(100, (stats.total_executions / max_executions) * 100)
        
        progress_text = Text()
        progress_text.append("Overall Progress\n", style="bold")
        progress_text.append(f"Executions: {stats.total_executions:,} / {max_executions:,}\n")
        progress_text.append(f"Progress: {progress_percent:.1f}%\n")
        
        if current_test:
            progress_text.append(f"\nCurrent Test:\n", style="bold")
            progress_text.append(f"Payload: {str(current_test.payload)[:50]}...\n")
            progress_text.append(f"Fitness: {current_test.fitness_score:.3f}\n")
            progress_text.append(f"Mutations: {len(current_test.mutation_path)}\n")
        
        return Panel(progress_text, title="Progress", border_style="blue")
    
    def create_current_test_panel(self) -> Panel:
        """Create the current test panel."""
        # Try to get current test case from feedback engine
        current_test = None
        if (self.feedback_engine and hasattr(self.feedback_engine, 'current_test_case')):
            current_test = self.feedback_engine.current_test_case
        
        if not current_test:
            return Panel("🔄 No test case active", title="🧪 Current Test", border_style="dim")
        
        content = Text()
        content.append("Current Payload:\n", style="bold blue")
        
        payload_str = str(current_test.payload)
        if len(payload_str) > 80:
            payload_str = payload_str[:80] + "..."
        
        # Truncate payload for display
        content.append(f"{payload_str}\n\n", style="white")
        
        # Coverage information
        if hasattr(current_test, 'coverage') and current_test.coverage:
            content.append("Coverage Info:\n", style="bold green")
            content.append(f"  Paths: {len(current_test.coverage.unique_paths)}\n", style="cyan")
            content.append(f"  Time: {current_test.coverage.execution_time:.3f}s\n", style="yellow")
            content.append(f"  Memory: {current_test.coverage.memory_usage:,} bytes\n\n", style="magenta")
        
        # Fitness score
        if hasattr(current_test, 'fitness_score'):
            content.append("Fitness Score:\n", style="bold")
            fitness = current_test.fitness_score
            fitness_color = "red" if fitness < 0.3 else "yellow" if fitness < 0.7 else "green"
            content.append(f"  {fitness:.3f}\n\n", style=fitness_color)
        
        # Mutation path
        if hasattr(current_test, 'mutation_path') and current_test.mutation_path:
            content.append("Mutation Path:\n", style="bold")
            path_str = " → ".join([str(m) for m in current_test.mutation_path[-3:]])  # Last 3 mutations
            content.append(f"{path_str}\n", style="dim")
        else:
            content.append("Initial test case\n", style="dim")
        
        return Panel(content, title="🧪 Current Test", border_style="green")
    
    def create_recent_findings_panel(self) -> Panel:
        """Create the recent findings panel."""
        if not self.feedback_engine or not hasattr(self.feedback_engine, 'test_cases'):
            return Panel("No findings data available", title="🔍 Recent Findings", border_style="dim")
        
        findings = []
        
        # Collect recent interesting findings
        for test_case in self.feedback_engine.test_cases.values():
            if hasattr(test_case, 'crash_info') and test_case.crash_info:
                findings.append((test_case, "Crash"))
            elif hasattr(test_case, 'fitness_score') and test_case.fitness_score > 0.5:
                findings.append((test_case, "Interesting"))
        
        if not findings:
            return Panel("🔍 No interesting findings yet", title="🔍 Recent Findings", border_style="dim")
        
        # Sort by fitness score
        findings.sort(key=lambda x: getattr(x[0], 'fitness_score', 0), reverse=True)
        
        findings_text = Text()
        findings_text.append(f"Total Findings: {len(findings):,}\n", style="cyan bold")
        
        # Show top 3 findings
        for i, (finding, finding_type) in enumerate(findings[:3]):
            fitness = getattr(finding, 'fitness_score', 0)
            payload = str(finding.payload)
            if len(payload) > 40:
                payload = payload[:40] + "..."
            
            # Color code the finding type
            type_color = "red" if finding_type == "Crash" else "yellow"
            
            findings_text.append(f"{i+1}. {finding_type}\n", style=f"{type_color} bold")
            findings_text.append(f"   Fitness: {fitness:.3f}\n", style="green")
            findings_text.append(f"   Payload: {payload}\n", style="white")
            
            if i < 2:  # Add separator except for last item
                findings_text.append("\n", style="dim")
        
        if len(findings) > 3:
            findings_text.append(f"\n... and {len(findings) - 3} more findings", style="dim")
        
        return Panel(findings_text, title="🔍 Recent Findings", border_style="yellow")
    
    def create_footer_panel(self) -> Panel:
        """Create the footer panel with status information."""
        if not self.feedback_engine:
            status_text = "Initializing..."
            status_style = "yellow"
        else:
            stats = self.feedback_engine.stats
            
            if stats.crashes_found > 0:
                status_text = "🚨 CRASHES DETECTED"
                status_style = "bright_red bold"
            elif stats.total_executions > 1000:
                status_text = "🚀 FUZZING ACTIVE"
                status_style = "green bold"
            elif stats.total_executions > 0:
                status_text = "🔄 FUZZING STARTED"
                status_style = "yellow bold"
            else:
                status_text = "⏳ INITIALIZING"
                status_style = "cyan bold"
        
        footer_text = Text()
        footer_text.append("Status: ", style="bold")
        footer_text.append(status_text, style=status_style)
        
        if self.feedback_engine and hasattr(self.feedback_engine, 'stats'):
            stats = self.feedback_engine.stats
            if stats.last_crash_time > 0:
                last_crash = datetime.fromtimestamp(stats.last_crash_time)
                footer_text.append(" | Last crash: ", style="dim")
                footer_text.append(last_crash.strftime('%H:%M:%S'), style="red")
        
        return Panel(
            Align.center(footer_text),
            box=box.ROUNDED,
            border_style="blue"
        )
    
    def update_footer(self) -> Panel:
        """Update the footer panel."""
        stats = self.feedback_engine.stats
        
        footer_text = Text()
        footer_text.append("Status: ", style="bold")
        
        if stats.crashes_found > 0:
            footer_text.append("CRASHES DETECTED", style="bright_red bold")
        elif stats.total_executions > 0:
            footer_text.append("FUZZING ACTIVE", style="green bold")
        else:
            footer_text.append("INITIALIZING", style="yellow bold")
        
        footer_text.append(" | ")
        footer_text.append(f"Last crash: ", style="bold")
        
        if stats.last_crash_time > 0:
            last_crash = datetime.fromtimestamp(stats.last_crash_time)
            footer_text.append(f"{last_crash.strftime('%H:%M:%S')}", style="red")
        else:
            footer_text.append("None", style="dim")
        
        return Panel(footer_text, box=box.ROUNDED)
    
    def show_enhanced_startup(self):
        """Show an enhanced startup sequence."""
        self.console.clear()
        
        # Create startup banner with animation
        startup_text = Text()
        startup_text.append("🧄 wpgarlic\n", style="bold blue")
        startup_text.append("Enhanced WordPress Plugin Fuzzer\n", style="cyan")
        startup_text.append("=" * 50 + "\n", style="dim")
        startup_text.append("Initializing components...\n", style="yellow")
        
        startup_panel = Panel(
            Align.center(startup_text),
            title="🚀 Starting Fuzzer",
            border_style="blue",
            padding=(2, 4)
        )
        
        self.console.print(startup_panel)
        
        # Show initialization steps
        steps = [
            "🔧 Setting up containers...",
            "📦 Installing WordPress...",
            "🔌 Loading plugin...",
            "🛠️ Applying patches...",
            "🎯 Discovering endpoints...",
            "✅ Ready to fuzz!"
        ]
        
        for i, step in enumerate(steps):
            time.sleep(0.5)  # Simulate initialization time
            self.console.print(f"[green]✓[/green] {step}")
        
        self.console.print()
    
    def show_crash_alert(self, crash_info: Dict[str, Any]):
        """Show an enhanced crash alert."""
        severity = crash_info.get("severity", "unknown")
        crash_type = crash_info.get("type", "unknown")
        timestamp = crash_info.get("timestamp", 0)
        
        severity_emoji = {
            CrashSeverity.LOW: "⚠️",
            CrashSeverity.MEDIUM: "🚨",
            CrashSeverity.HIGH: "💥",
            CrashSeverity.CRITICAL: "🔥"
        }.get(severity, "❓")
        
        severity_color = {
            CrashSeverity.LOW: "yellow",
            CrashSeverity.MEDIUM: "orange1", 
            CrashSeverity.HIGH: "red1",
            CrashSeverity.CRITICAL: "bright_red"
        }.get(severity, "white")
        
        alert_text = Text()
        alert_text.append(f"{severity_emoji} CRASH DETECTED {severity_emoji}\n", style=f"{severity_color} bold")
        alert_text.append(f"Type: {crash_type}\n", style="cyan")
        alert_text.append(f"Severity: {severity.value.upper()}\n", style=severity_color)
        
        if timestamp:
            alert_text.append(f"Time: {datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')}\n", style="dim")
        
        crash_panel = Panel(
            Align.center(alert_text),
            title="🚨 CRASH ALERT",
            border_style="red",
            padding=(1, 2)
        )
        
        self.console.print(crash_panel)
    
    def show_final_summary(self):
        """Show an enhanced final summary."""
        if not self.feedback_engine:
            return
        
        stats = self.feedback_engine.stats
        uptime = time.time() - self.start_time
        
        summary_text = Text()
        summary_text.append("🎉 FUZZING SESSION COMPLETE 🎉\n\n", style="bold green")
        summary_text.append(f"🎯 Plugin: {self.current_plugin}\n", style="cyan")
        summary_text.append(f"⏱️ Duration: {timedelta(seconds=int(uptime))}\n", style="yellow")
        summary_text.append(f"🚀 Total Executions: {stats.total_executions:,}\n", style="blue")
        summary_text.append(f"⚡ Average Speed: {stats.executions_per_second:.1f} exec/sec\n", style="green")
        summary_text.append(f"📊 Coverage Lines: {stats.total_coverage:,}\n", style="magenta")
        summary_text.append(f"💥 Crashes Found: {stats.crashes_found:,}\n", style="red")
        summary_text.append(f"🔍 Unique Crashes: {stats.unique_crashes:,}\n", style="red")
        
        summary_panel = Panel(
            Align.center(summary_text),
            title="📋 Session Summary",
            border_style="green",
            padding=(2, 4)
        )
        
        self.console.print(summary_panel)
    
    def print_status(self, message: str, style: str = "white"):
        """Print a status message with enhanced formatting."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.print(f"[dim]{timestamp}[/dim] [{style}]{message}[/{style}]")
    
    def print_error(self, message: str):
        """Print an error message with enhanced formatting."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.print(f"[dim]{timestamp}[/dim] [red]Error:[/red] {message}")
    
    def print_warning(self, message: str):
        """Print a warning message with enhanced formatting."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.print(f"[dim]{timestamp}[/dim] [yellow]Warning:[/yellow] {message}")
    
    def print_success(self, message: str):
        """Print a success message with enhanced formatting."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.print(f"[dim]{timestamp}[/dim] [green]Success:[/green] {message}")
    
    def print_info(self, message: str):
        """Print an info message with enhanced formatting."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.print(f"[dim]{timestamp}[/dim] [blue]Info:[/blue] {message}")
    
    def print_crash(self, message: str):
        """Print a crash message with enhanced formatting."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.print(f"[dim]{timestamp}[/dim] [red]Crash:[/red] {message}")
    
    def create_progress_display(self, current: int, total: int, description: str = "") -> str:
        """Create a visual progress bar string."""
        if total == 0:
            return f"[red]Error: Total is 0[/red]"
        
        percentage = min(100, (current / total) * 100)
        bar_length = 30
        filled = int((percentage / 100) * bar_length)
        bar = "█" * filled + "░" * (bar_length - filled)
        
        return f"[green]{description}[/green] [{bar}] {percentage:.1f}% ({current:,}/{total:,})"
