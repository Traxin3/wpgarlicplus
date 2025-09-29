# Enhanced wpgarlic - Feedback-Guided WordPress Plugin Fuzzing

This enhanced version of wpgarlic implements AFL++-like feedback-guided fuzzing capabilities with advanced coverage tracking, intelligent mutation strategies, and a modern Rich-based console interface.

## 🚀 New Features

### Feedback-Guided Fuzzing
- **Coverage Tracking**: Real-time code coverage analysis to identify new code paths
- **Input Prioritization**: Smart test case prioritization based on coverage and fitness scores
- **Mutation Strategies**: Multiple mutation strategies (bit flip, arithmetic, dictionary, havoc, splice)
- **Path Discovery**: Automatic discovery of interesting execution paths

### Advanced UI
- **Rich Console Interface**: Beautiful real-time terminal UI with progress bars, statistics, and live updates
- **Live Coverage Visualization**: Real-time coverage maps and statistics
- **Crash Analysis Dashboard**: Detailed crash analysis with severity classification
- **Performance Metrics**: Comprehensive performance and effectiveness tracking

### Enhanced Crash Detection
- **Smart Deduplication**: Advanced crash deduplication to reduce false positives
- **Severity Classification**: Automatic severity assessment (Low, Medium, High, Critical)
- **Exploitability Analysis**: Assessment of crash exploitability potential
- **CWE Mapping**: Automatic mapping to Common Weakness Enumeration (CWE) IDs

### Configuration System
- **Multiple Modes**: Fast, Balanced, and Deep fuzzing modes
- **Flexible Configuration**: Comprehensive configuration system for all fuzzing parameters
- **Preset Configurations**: Pre-configured settings for different use cases
- **Runtime Adaptation**: Dynamic configuration adjustment based on results

## 📦 Installation

1. **Install Dependencies**:
   ```bash
   # For minimal installation (recommended)
   pip install -r requirements-minimal.txt
   
   # For full installation with dev tools
   pip install -r requirements.txt
   
   # For development
   pip install -r requirements-dev.txt
   ```

2. **Setup Docker Environment**:
   ```bash
   docker-compose build
   ```

3. **Generate Configuration** (Optional):
   ```bash
   ./bin/generate_config balanced --output config.json
   ```

## 🎯 Usage

### Basic Usage
```bash
# Fuzz a plugin with default balanced mode
./bin/enhanced_fuzz fuzz my-plugin

# Fuzz with specific version
./bin/enhanced_fuzz fuzz my-plugin --version 1.2.3

# Use fast mode for quick testing
./bin/enhanced_fuzz fuzz my-plugin --mode fast

# Use deep mode for thorough analysis
./bin/enhanced_fuzz fuzz my-plugin --mode deep

# Use custom configuration
./bin/enhanced_fuzz fuzz my-plugin --config my_config.json
```

### Configuration Generation
```bash
# Generate fast mode configuration
./bin/generate_config fast --output fast_config.json

# Generate deep mode configuration  
./bin/generate_config deep --output deep_config.json

# Generate balanced mode configuration
./bin/generate_config balanced --output balanced_config.json
```

### Output Directory Structure
```
fuzzing_results/
├── coverage/                 # Coverage reports and data
├── crashes/                  # Crash analysis reports
├── checkpoints/              # Fuzzing state checkpoints
├── final_state.json         # Final fuzzing state
├── coverage_report.json     # Detailed coverage report
└── crash_report.json        # Detailed crash analysis
```

## ⚙️ Configuration

### Fuzzing Modes

#### Fast Mode
- **Max Executions**: 10,000
- **Max Test Cases**: 1,000
- **Execution Timeout**: 5 seconds
- **Focus**: Quick vulnerability discovery

#### Balanced Mode (Default)
- **Max Executions**: 50,000
- **Max Test Cases**: 5,000
- **Execution Timeout**: 15 seconds
- **Focus**: Good balance of speed and thoroughness

#### Deep Mode
- **Max Executions**: 200,000
- **Max Test Cases**: 20,000
- **Execution Timeout**: 30 seconds
- **Focus**: Comprehensive vulnerability analysis

### Mutation Strategies

The enhanced fuzzer uses multiple mutation strategies:

1. **Bit Flip** (20%): Random bit flipping in payloads
2. **Arithmetic** (15%): Arithmetic operations on numeric values
3. **Dictionary** (20%): Dictionary-based mutations using known patterns
4. **Havoc** (25%): Random combinations of mutations
5. **Splice** (10%): Combining payloads from different test cases
6. **Interesting** (10%): Using known interesting values

### Coverage Tracking

- **Line Coverage**: Track individual line execution
- **Function Coverage**: Track function calls and execution
- **Branch Coverage**: Track conditional branch execution
- **Path Coverage**: Track unique execution paths
- **File Coverage**: Track file inclusion and execution

### Crash Analysis

The enhanced crash analyzer detects and classifies:

- **SQL Injection**: Database-related vulnerabilities
- **XSS**: Cross-site scripting vulnerabilities  
- **File Inclusion**: Local/remote file inclusion
- **Command Injection**: System command execution
- **Memory Errors**: Buffer overflows and memory issues
- **Type Errors**: PHP type-related errors
- **Stack Overflow**: Function nesting issues

## 📊 Real-Time Interface

The Rich console interface provides:

### Statistics Panel
- Total executions and execution rate
- Coverage metrics and growth rate
- Crash counts and discovery rate
- Queue size and test case count

### Coverage Panel
- File-by-file coverage breakdown
- Function coverage statistics
- Branch coverage analysis
- Path discovery metrics

### Crashes Panel
- Recent crash discoveries
- Severity classification
- Crash type breakdown
- Exploitability assessment

### Progress Panel
- Overall fuzzing progress
- Current test case information
- Mutation strategy tracking
- Performance metrics

## 🔧 Advanced Features

### Coverage Instrumentation

The system includes enhanced PHP instrumentation:

```php
// Automatic coverage tracking
wpgarlic_track_function($function_name, $file, $line);
wpgarlic_track_line($file, $line, $context);
wpgarlic_track_branch($file, $line, $branch_id, $taken);
```

### Feedback Engine

The feedback engine provides:

- **Fitness Scoring**: Multi-factor fitness calculation
- **Input Queue Management**: Priority-based test case queue
- **Mutation Generation**: Intelligent mutation strategies
- **Coverage Analysis**: Real-time coverage tracking

### Crash Deduplication

Advanced deduplication features:

- **Signature-based**: Exact crash signature matching
- **Similarity Analysis**: Fuzzy matching for similar crashes
- **Cluster Analysis**: Grouping related crashes
- **Confidence Scoring**: Reliability assessment

## 📈 Performance Optimization

### Resource Management
- **Memory Limits**: Configurable memory usage limits
- **CPU Limits**: CPU usage monitoring and limits
- **Execution Timeouts**: Per-test-case timeout controls
- **Parallel Execution**: Optional parallel fuzzing support

### Statistics Tracking
- **Performance Metrics**: Execution time and memory usage
- **Coverage Growth**: Coverage expansion rate tracking
- **Crash Discovery Rate**: Vulnerability discovery metrics
- **Efficiency Analysis**: Fuzzing effectiveness measurement

## 🛡️ Security Considerations

### Isolation
- **Network Isolation**: Disconnected network during fuzzing
- **DNS Isolation**: Disabled DNS resolution
- **Container Isolation**: Docker-based isolation

### Safety Features
- **Timeout Controls**: Prevents infinite loops
- **Resource Limits**: Prevents resource exhaustion
- **Error Handling**: Graceful error recovery
- **State Persistence**: Checkpoint-based state saving

## 🔍 Troubleshooting

### Common Issues

1. **Docker Issues**:
   ```bash
   # Rebuild containers
   docker-compose down
   docker-compose build
   docker-compose up -d
   ```

2. **Permission Issues**:
   ```bash
   # Fix file permissions
   chmod +x bin/enhanced_fuzz
   chmod +x bin/generate_config
   ```

3. **Memory Issues**:
   - Reduce `max_test_cases` in configuration
   - Increase `max_memory_usage` limit
   - Use fast mode for memory-constrained environments

### Debug Mode

Enable debug logging:
```bash
# Set debug environment variable
export WPGARLIC_DEBUG=1

# Run with verbose output
./bin/enhanced_fuzz fuzz my-plugin --mode fast
```

## 📚 API Reference

### Configuration Classes

- `FuzzingConfiguration`: Main configuration class
- `MutationConfig`: Mutation strategy configuration
- `CoverageConfig`: Coverage tracking configuration
- `CrashConfig`: Crash detection configuration
- `PerformanceConfig`: Performance and resource configuration
- `OutputConfig`: Output and reporting configuration
- `WordPressConfig`: WordPress-specific configuration

### Core Classes

- `EnhancedFuzzer`: Main fuzzing orchestrator
- `FeedbackEngine`: AFL++-like feedback system
- `CoverageTracker`: Coverage analysis system
- `EnhancedCrashAnalyzer`: Advanced crash analysis
- `FuzzingConsole`: Rich console interface

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project maintains the same license as the original wpgarlic project.

## 🙏 Acknowledgments

- Original wpgarlic authors for the excellent foundation
- AFL++ team for inspiration on feedback-guided fuzzing
- Rich library authors for the beautiful console interface
- WordPress security community for vulnerability patterns

---

For more information, see the original wpgarlic documentation and the enhanced fuzzing system code comments.
