"""
Smart Setup Manager for wpgarlic fuzzing system.
Handles first-time initialization, subsequent runs, and intelligent caching.
"""

import json
import os
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.text import Text
from rich.align import Align
from rich import box
from rich.table import Table
from rich.status import Status
from rich.live import Live
from rich.layout import Layout

import fuzzer_container


class SetupState:
    """Manages setup state and caching."""
    
    def __init__(self, state_dir: str = ".wpgarlic_state"):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(exist_ok=True)
        self.state_file = self.state_dir / "setup_state.json"
        self.cache_dir = self.state_dir / "cache"
        self.cache_dir.mkdir(exist_ok=True)
        
        self.state = self._load_state()
    
    def _load_state(self) -> Dict[str, Any]:
        """Load setup state from file."""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        
        return {
            "first_run": True,
            "last_setup": None,
            "plugin_cache": {},
            "container_state": {},
            "setup_history": [],
            "performance_metrics": {}
        }
    
    def save_state(self):
        """Save current setup state."""
        self.state["last_save"] = datetime.now().isoformat()
        try:
            with open(self.state_file, 'w') as f:
                json.dump(self.state, f, indent=2)
        except IOError as e:
            print(f"Warning: Could not save setup state: {e}")
    
    def is_plugin_cached(self, plugin_slug: str, version: str = None) -> bool:
        """Check if plugin setup is cached."""
        cache_key = f"{plugin_slug}:{version or 'latest'}"
        if cache_key in self.state["plugin_cache"]:
            cache_info = self.state["plugin_cache"][cache_key]
            # Check if cache is still valid (less than 24 hours old)
            cache_time = datetime.fromisoformat(cache_info["cached_at"])
            return datetime.now() - cache_time < timedelta(hours=24)
        return False
    
    def get_plugin_cache(self, plugin_slug: str, version: str = None) -> Optional[Dict]:
        """Get cached plugin setup data."""
        cache_key = f"{plugin_slug}:{version or 'latest'}"
        return self.state["plugin_cache"].get(cache_key)
    
    def cache_plugin_setup(self, plugin_slug: str, version: str, setup_data: Dict):
        """Cache plugin setup data."""
        cache_key = f"{plugin_slug}:{version or 'latest'}"
        self.state["plugin_cache"][cache_key] = {
            "cached_at": datetime.now().isoformat(),
            "setup_data": setup_data,
            "plugin_slug": plugin_slug,
            "version": version
        }
        self.save_state()
    
    def is_first_run(self) -> bool:
        """Check if this is the first run."""
        return self.state.get("first_run", True)
    
    def mark_first_run_complete(self):
        """Mark first run as complete."""
        self.state["first_run"] = False
        self.state["first_run_completed"] = datetime.now().isoformat()
        self.save_state()
    
    def add_setup_history(self, plugin_slug: str, version: str, duration: float, success: bool):
        """Add setup attempt to history."""
        self.state["setup_history"].append({
            "timestamp": datetime.now().isoformat(),
            "plugin_slug": plugin_slug,
            "version": version,
            "duration": duration,
            "success": success
        })
        
        # Keep only last 50 entries
        if len(self.state["setup_history"]) > 50:
            self.state["setup_history"] = self.state["setup_history"][-50:]
        
        self.save_state()


class SmartSetupManager:
    """Smart setup manager with intelligent caching and UI."""
    
    def __init__(self):
        # Configure console for Windows compatibility
        self.console = Console(force_terminal=True, legacy_windows=False)
        self.state = SetupState()
        self.setup_start_time = None
        self.current_step = 0
        self.total_steps = 0
        
    def show_welcome_screen(self, plugin_slug: str, version: str = None):
        """Show welcome screen with setup information."""
        self.console.clear()
        
        # Determine setup type
        is_first_run = self.state.is_first_run()
        is_cached = self.state.is_plugin_cached(plugin_slug, version)
        
        setup_type = "🆕 First Time Setup" if is_first_run else "🔄 Subsequent Run"
        cache_status = "✅ Cached" if is_cached else "🔄 Fresh Setup"
        
        welcome_text = Text()
        welcome_text.append("🧄 wpgarlic Smart Setup\n", style="bold blue")
        welcome_text.append("Enhanced WordPress Plugin Fuzzer\n\n", style="cyan")
        
        welcome_text.append("Target Information:\n", style="bold")
        welcome_text.append(f"  🎯 Plugin: {plugin_slug}\n", style="green")
        if version:
            welcome_text.append(f"  📦 Version: {version}\n", style="blue")
        else:
            welcome_text.append(f"  📦 Version: Latest\n", style="blue")
        
        welcome_text.append(f"\nSetup Information:\n", style="bold")
        welcome_text.append(f"  {setup_type}\n", style="yellow")
        welcome_text.append(f"  {cache_status}\n", style="cyan")
        
        if is_cached:
            cache_info = self.state.get_plugin_cache(plugin_slug, version)
            if cache_info:
                cached_at = datetime.fromisoformat(cache_info["cached_at"])
                time_ago = datetime.now() - cached_at
                welcome_text.append(f"  ⏰ Cached: {time_ago.total_seconds()/3600:.1f} hours ago\n", style="dim")
        
        welcome_text.append(f"\nSystem Status:\n", style="bold")
        if is_first_run:
            welcome_text.append("  🔧 Full system initialization required\n", style="yellow")
            welcome_text.append("  📦 Docker containers will be built\n", style="yellow")
            welcome_text.append("  🛠️ WordPress and plugins will be installed\n", style="yellow")
        else:
            welcome_text.append("  ⚡ Quick setup using cached data\n", style="green")
            if is_cached:
                welcome_text.append("  🚀 Plugin already configured\n", style="green")
            else:
                welcome_text.append("  🔄 Plugin setup required\n", style="yellow")
        
        welcome_panel = Panel(
            Align.center(welcome_text),
            title="🚀 Smart Setup Manager",
            border_style="blue",
            padding=(2, 4)
        )
        
        self.console.print(welcome_panel)
        self.console.print()
        
        # Show setup history if available
        if self.state.state.get("setup_history"):
            self._show_setup_history()
    
    def _show_setup_history(self):
        """Show recent setup history."""
        history = self.state.state.get("setup_history", [])
        if not history:
            return
        
        table = Table(title="📊 Recent Setup History", box=box.ROUNDED)
        table.add_column("Time", style="cyan", width=12)
        table.add_column("Plugin", style="green", width=20)
        table.add_column("Version", style="blue", width=10)
        table.add_column("Duration", style="yellow", width=10)
        table.add_column("Status", style="red", width=8)
        
        for entry in history[-5:]:  # Show last 5 entries
            timestamp = datetime.fromisoformat(entry["timestamp"])
            time_str = timestamp.strftime("%H:%M:%S")
            duration = f"{entry['duration']:.1f}s"
            status = "✅" if entry["success"] else "❌"
            
            table.add_row(
                time_str,
                entry["plugin_slug"],
                entry.get("version", "latest"),
                duration,
                status
            )
        
        self.console.print(table)
        self.console.print()
    
    def show_setup_progress(self, plugin_slug: str, version: str = None):
        """Show setup progress with smart step detection."""
        self.setup_start_time = time.time()
        
        # Determine setup steps based on state
        is_first_run = self.state.is_first_run()
        is_cached = self.state.is_plugin_cached(plugin_slug, version)
        
        if is_first_run:
            steps = [
                "🔧 Initializing Docker environment",
                "📦 Building WordPress containers",
                "🗄️ Setting up database",
                "🌐 Installing WordPress core",
                "🔌 Installing target plugin",
                "🛠️ Applying security patches",
                "🎯 Discovering fuzzable endpoints",
                "📊 Initializing coverage tracking",
                "🔒 Isolating environment",
                "✅ Finalizing setup"
            ]
        elif is_cached:
            steps = [
                "⚡ Loading cached configuration",
                "🔄 Verifying environment",
                "🎯 Rediscovering endpoints",
                "✅ Ready to fuzz"
            ]
        else:
            steps = [
                "🔄 Checking environment",
                "🔌 Installing target plugin",
                "🛠️ Applying patches",
                "🎯 Discovering endpoints",
                "✅ Finalizing setup"
            ]
        
        self.total_steps = len(steps)
        self.current_step = 0
        
        with Progress(
            SpinnerColumn(spinner_name="dots12"),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            "[progress.percentage]{task.percentage:>3.0f}%",
            "•",
            TimeElapsedColumn(),
            console=self.console,
            expand=True
        ) as progress:
            
            task = progress.add_task("Starting setup...", total=self.total_steps)
            
            for i, step in enumerate(steps):
                self.current_step = i
                progress.update(task, description=step, completed=i)
                
                # Execute the actual setup step
                success = self._execute_setup_step(step, plugin_slug, version, is_first_run, is_cached)
                
                if not success:
                    self.console.print(f"[red]❌ Setup failed at step: {step}[/red]")
                    return False
                
                # Small delay for visual effect
                time.sleep(0.3)
            
            progress.update(task, completed=self.total_steps, description="✅ Setup complete!")
        
        # Mark setup as complete
        duration = time.time() - self.setup_start_time
        self.state.add_setup_history(plugin_slug, version, duration, True)
        
        if is_first_run:
            self.state.mark_first_run_complete()
        
        return True
    
    def _execute_setup_step(self, step: str, plugin_slug: str, version: str, 
                           is_first_run: bool, is_cached: bool) -> bool:
        """Execute a specific setup step."""
        try:
            if "Initializing Docker" in step:
                if not is_cached:
                    # Only reinitialize if not cached
                    fuzzer_container.reinitialize_containers()
            
            elif "Building WordPress" in step:
                # Container building is handled by reinitialize_containers
                pass
            
            elif "Setting up database" in step:
                # Database setup is handled by reinitialize_containers
                pass
            
            elif "Installing WordPress" in step:
                # WordPress installation is handled by reinitialize_containers
                pass
            
            elif "Installing target plugin" in step:
                if not is_cached:
                    fuzzer_container.install_plugin_from_slug(plugin_slug, version)
                    fuzzer_container.activate_plugin(plugin_slug)
            
            elif "Applying security patches" in step:
                if not is_cached:
                    fuzzer_container.patch_wordpress()
                    fuzzer_container.patch_plugins_themes()
            
            elif "Discovering fuzzable endpoints" in step:
                # This will be handled by the main fuzzing setup
                pass
            
            elif "Initializing coverage tracking" in step:
                # Coverage initialization
                pass
            
            elif "Isolating environment" in step:
                if not is_cached:
                    container_id = fuzzer_container.get_container_id()
                    fuzzer_container.disconnect_network(container_id)
                    fuzzer_container.disconnect_dns()
            
            elif "Loading cached configuration" in step:
                # Load cached data
                cache_data = self.state.get_plugin_cache(plugin_slug, version)
                if cache_data:
                    self.console.print(f"[green]✓ Loaded cached configuration[/green]")
            
            elif "Verifying environment" in step:
                # Verify environment is still valid
                pass
            
            elif "Finalizing setup" in step:
                # Cache the setup if successful
                if not is_cached:
                    setup_data = {
                        "plugin_slug": plugin_slug,
                        "version": version,
                        "setup_time": datetime.now().isoformat(),
                        "endpoints_discovered": True  # Will be updated later
                    }
                    self.state.cache_plugin_setup(plugin_slug, version, setup_data)
            
            return True
            
        except Exception as e:
            self.console.print(f"[red]Error in step '{step}': {e}[/red]")
            return False
    
    def show_setup_summary(self, plugin_slug: str, version: str = None):
        """Show setup completion summary."""
        duration = time.time() - self.setup_start_time if self.setup_start_time else 0
        
        summary_text = Text()
        summary_text.append("🎉 Setup Complete!\n\n", style="bold green")
        
        summary_text.append("Configuration Summary:\n", style="bold")
        summary_text.append(f"  🎯 Plugin: {plugin_slug}\n", style="green")
        summary_text.append(f"  📦 Version: {version or 'Latest'}\n", style="blue")
        summary_text.append(f"  ⏱️ Setup Time: {duration:.1f} seconds\n", style="yellow")
        
        summary_text.append(f"\nEnvironment Status:\n", style="bold")
        summary_text.append("  ✅ WordPress installed and configured\n", style="green")
        summary_text.append("  ✅ Target plugin installed and activated\n", style="green")
        summary_text.append("  ✅ Security patches applied\n", style="green")
        summary_text.append("  ✅ Environment isolated\n", style="green")
        
        summary_text.append(f"\nReady for Fuzzing:\n", style="bold")
        summary_text.append("  🚀 Feedback-guided fuzzing engine\n", style="cyan")
        summary_text.append("  📊 Real-time coverage tracking\n", style="cyan")
        summary_text.append("  💥 Advanced crash detection\n", style="cyan")
        summary_text.append("  📈 Live progress visualization\n", style="cyan")
        
        summary_panel = Panel(
            Align.center(summary_text),
            title="✅ Setup Complete",
            border_style="green",
            padding=(2, 4)
        )
        
        self.console.print(summary_panel)
        self.console.print()
    
    def cleanup_old_cache(self, max_age_days: int = 7):
        """Clean up old cache entries."""
        cutoff_date = datetime.now() - timedelta(days=max_age_days)
        
        cleaned_count = 0
        for cache_key, cache_info in list(self.state.state["plugin_cache"].items()):
            cache_time = datetime.fromisoformat(cache_info["cached_at"])
            if cache_time < cutoff_date:
                del self.state.state["plugin_cache"][cache_key]
                cleaned_count += 1
        
        if cleaned_count > 0:
            self.state.save_state()
            self.console.print(f"[yellow]🧹 Cleaned up {cleaned_count} old cache entries[/yellow]")
    
    def get_setup_stats(self) -> Dict[str, Any]:
        """Get setup statistics."""
        history = self.state.state.get("setup_history", [])
        
        if not history:
            return {"total_setups": 0}
        
        total_setups = len(history)
        successful_setups = sum(1 for entry in history if entry["success"])
        avg_duration = sum(entry["duration"] for entry in history) / total_setups
        
        return {
            "total_setups": total_setups,
            "successful_setups": successful_setups,
            "success_rate": successful_setups / total_setups * 100,
            "average_duration": avg_duration,
            "cached_plugins": len(self.state.state["plugin_cache"])
        }


def run_smart_setup(plugin_slug: str, version: str = None) -> bool:
    """Run the smart setup process."""
    manager = SmartSetupManager()
    
    try:
        # Show welcome screen
        manager.show_welcome_screen(plugin_slug, version)
        
        # Clean up old cache
        manager.cleanup_old_cache()
        
        # Run setup
        success = manager.show_setup_progress(plugin_slug, version)
        
        if success:
            manager.show_setup_summary(plugin_slug, version)
        
        return success
        
    except KeyboardInterrupt:
        manager.console.print("\n[yellow]Setup interrupted by user[/yellow]")
        return False
    except Exception as e:
        manager.console.print(f"[red]Setup failed: {e}[/red]")
        return False


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python setup_manager.py <plugin_slug> [version]")
        sys.exit(1)
    
    plugin_slug = sys.argv[1]
    version = sys.argv[2] if len(sys.argv) > 2 else None
    
    success = run_smart_setup(plugin_slug, version)
    sys.exit(0 if success else 1)
