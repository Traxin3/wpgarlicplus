<?php
/**
 * Enhanced coverage instrumentation for wpgarlic fuzzing.
 * Provides detailed code coverage tracking and path analysis.
 */

// Coverage tracking globals
$GLOBALS['__wpgarlic_coverage'] = [
    'files' => [],
    'functions' => [],
    'branches' => [],
    'lines' => [],
    'paths' => [],
    'start_time' => microtime(true),
    'memory_start' => memory_get_usage()
];

// Coverage output file
$GLOBALS['__wpgarlic_coverage_file'] = '/tmp/wpgarlic_coverage.json';

/**
 * Initialize coverage tracking
 */
function wpgarlic_init_coverage() {
    global $__wpgarlic_coverage;
    
    // Register shutdown function to save coverage data
    register_shutdown_function('wpgarlic_save_coverage');
    
    // Set up error handler for coverage tracking
    set_error_handler('wpgarlic_coverage_error_handler');
    
    // Initialize coverage data
    $__wpgarlic_coverage['start_time'] = microtime(true);
    $__wpgarlic_coverage['memory_start'] = memory_get_usage();
}

/**
 * Track function entry
 */
function wpgarlic_track_function($function_name, $file, $line) {
    global $__wpgarlic_coverage;
    
    $key = $file . ':' . $function_name;
    
    if (!isset($__wpgarlic_coverage['functions'][$key])) {
        $__wpgarlic_coverage['functions'][$key] = [
            'name' => $function_name,
            'file' => $file,
            'line' => $line,
            'count' => 0,
            'first_hit' => microtime(true),
            'last_hit' => microtime(true)
        ];
    }
    
    $__wpgarlic_coverage['functions'][$key]['count']++;
    $__wpgarlic_coverage['functions'][$key]['last_hit'] = microtime(true);
    
    // Output coverage marker
    fwrite(STDERR, "__COVERAGE_FUNCTION__" . $key . "__ENDCOVERAGE__\n");
}

/**
 * Track line execution
 */
function wpgarlic_track_line($file, $line, $context = '') {
    global $__wpgarlic_coverage;
    
    $key = $file . ':' . $line;
    
    if (!isset($__wpgarlic_coverage['lines'][$key])) {
        $__wpgarlic_coverage['lines'][$key] = [
            'file' => $file,
            'line' => $line,
            'count' => 0,
            'first_hit' => microtime(true),
            'last_hit' => microtime(true),
            'context' => $context
        ];
    }
    
    $__wpgarlic_coverage['lines'][$key]['count']++;
    $__wpgarlic_coverage['lines'][$key]['last_hit'] = microtime(true);
    
    // Output coverage marker
    fwrite(STDERR, "__COVERAGE_LINE__" . $key . "__ENDCOVERAGE__\n");
}

/**
 * Track branch execution
 */
function wpgarlic_track_branch($file, $line, $branch_id, $taken = true) {
    global $__wpgarlic_coverage;
    
    $key = $file . ':' . $line . ':' . $branch_id;
    
    if (!isset($__wpgarlic_coverage['branches'][$key])) {
        $__wpgarlic_coverage['branches'][$key] = [
            'file' => $file,
            'line' => $line,
            'branch_id' => $branch_id,
            'taken_count' => 0,
            'not_taken_count' => 0,
            'first_hit' => microtime(true),
            'last_hit' => microtime(true)
        ];
    }
    
    if ($taken) {
        $__wpgarlic_coverage['branches'][$key]['taken_count']++;
    } else {
        $__wpgarlic_coverage['branches'][$key]['not_taken_count']++;
    }
    
    $__wpgarlic_coverage['branches'][$key]['last_hit'] = microtime(true);
    
    // Output coverage marker
    fwrite(STDERR, "__COVERAGE_BRANCH__" . $key . ":" . ($taken ? 'T' : 'F') . "__ENDCOVERAGE__\n");
}

/**
 * Track file inclusion
 */
function wpgarlic_track_file($file) {
    global $__wpgarlic_coverage;
    
    if (!isset($__wpgarlic_coverage['files'][$file])) {
        $__wpgarlic_coverage['files'][$file] = [
            'file' => $file,
            'included' => true,
            'first_hit' => microtime(true),
            'last_hit' => microtime(true)
        ];
    } else {
        $__wpgarlic_coverage['files'][$file]['last_hit'] = microtime(true);
    }
    
    // Output coverage marker
    fwrite(STDERR, "__COVERAGE_FILE__" . $file . "__ENDCOVERAGE__\n");
}

/**
 * Track execution path
 */
function wpgarlic_track_path($path_element) {
    global $__wpgarlic_coverage;
    
    $__wpgarlic_coverage['paths'][] = [
        'element' => $path_element,
        'timestamp' => microtime(true)
    ];
    
    // Output coverage marker
    fwrite(STDERR, "__COVERAGE_PATH__" . $path_element . "__ENDCOVERAGE__\n");
}

/**
 * Get coverage statistics
 */
function wpgarlic_get_coverage_stats() {
    global $__wpgarlic_coverage;
    
    $total_files = count($__wpgarlic_coverage['files']);
    $total_functions = count($__wpgarlic_coverage['functions']);
    $total_lines = count($__wpgarlic_coverage['lines']);
    $total_branches = count($__wpgarlic_coverage['branches']);
    $total_paths = count($__wpgarlic_coverage['paths']);
    
    $execution_time = microtime(true) - $__wpgarlic_coverage['start_time'];
    $memory_usage = memory_get_usage() - $__wpgarlic_coverage['memory_start'];
    
    return [
        'files' => $total_files,
        'functions' => $total_functions,
        'lines' => $total_lines,
        'branches' => $total_branches,
        'paths' => $total_paths,
        'execution_time' => $execution_time,
        'memory_usage' => $memory_usage
    ];
}

/**
 * Save coverage data to file
 */
function wpgarlic_save_coverage() {
    global $__wpgarlic_coverage, $__wpgarlic_coverage_file;
    
    $coverage_data = [
        'timestamp' => time(),
        'stats' => wpgarlic_get_coverage_stats(),
        'files' => $__wpgarlic_coverage['files'],
        'functions' => $__wpgarlic_coverage['functions'],
        'branches' => $__wpgarlic_coverage['branches'],
        'lines' => $__wpgarlic_coverage['lines'],
        'paths' => $__wpgarlic_coverage['paths']
    ];
    
    file_put_contents($__wpgarlic_coverage_file, json_encode($coverage_data, JSON_PRETTY_PRINT));
    
    // Output final coverage summary
    fwrite(STDERR, "__COVERAGE_SUMMARY__" . json_encode($coverage_data['stats']) . "__ENDCOVERAGE__\n");
}

/**
 * Coverage error handler
 */
function wpgarlic_coverage_error_handler($errno, $errstr, $errfile, $errline, $errcontext) {
    // Track error as coverage point
    wpgarlic_track_line($errfile, $errline, "ERROR: " . $errstr);
    
    // Call original error handler
    return false;
}

/**
 * Enhanced function wrapper for WordPress functions
 */
function wpgarlic_wrap_wordpress_function($function_name, $callback) {
    return function() use ($function_name, $callback) {
        // Track function entry
        $backtrace = debug_backtrace();
        $caller = $backtrace[1];
        wpgarlic_track_function($function_name, $caller['file'], $caller['line']);
        
        // Track execution path
        wpgarlic_track_path($function_name);
        
        // Call original function
        $result = call_user_func_array($callback, func_get_args());
        
        return $result;
    };
}

/**
 * Instrument WordPress core functions
 */
function wpgarlic_instrument_wordpress() {
    // Wrap common WordPress functions
    $functions_to_wrap = [
        'wp_insert_post',
        'wp_update_post',
        'wp_delete_post',
        'get_posts',
        'add_action',
        'add_filter',
        'wp_enqueue_script',
        'wp_enqueue_style',
        'get_option',
        'update_option',
        'delete_option',
        'wp_mail',
        'wp_redirect',
        'wp_safe_redirect'
    ];
    
    foreach ($functions_to_wrap as $func) {
        if (function_exists($func)) {
            $original_func = $func;
            $GLOBALS['__wpgarlic_original_' . $func] = $original_func;
            
            // Create wrapper function
            $GLOBALS[$func] = wpgarlic_wrap_wordpress_function($func, $original_func);
        }
    }
}

/**
 * Instrument plugin functions
 */
function wpgarlic_instrument_plugin($plugin_file) {
    if (!file_exists($plugin_file)) {
        return;
    }
    
    // Track file inclusion
    wpgarlic_track_file($plugin_file);
    
    // Read plugin content
    $content = file_get_contents($plugin_file);
    
    // Parse and instrument functions
    $functions = wpgarlic_parse_functions($content, $plugin_file);
    
    foreach ($functions as $function) {
        wpgarlic_track_function($function['name'], $plugin_file, $function['line']);
    }
}

/**
 * Parse functions from PHP content
 */
function wpgarlic_parse_functions($content, $file) {
    $functions = [];
    $lines = explode("\n", $content);
    
    $function_patterns = [
        '/function\s+(\w+)\s*\(/',
        '/public\s+function\s+(\w+)\s*\(/',
        '/private\s+function\s+(\w+)\s*\(/',
        '/protected\s+function\s+(\w+)\s*\(/',
        '/static\s+function\s+(\w+)\s*\(/'
    ];
    
    foreach ($lines as $line_num => $line) {
        foreach ($function_patterns as $pattern) {
            if (preg_match($pattern, $line, $matches)) {
                $functions[] = [
                    'name' => $matches[1],
                    'line' => $line_num + 1,
                    'file' => $file
                ];
            }
        }
    }
    
    return $functions;
}

/**
 * Initialize coverage tracking for fuzzing
 */
function wpgarlic_init_fuzzing_coverage() {
    // Initialize coverage tracking
    wpgarlic_init_coverage();
    
    // Instrument WordPress
    wpgarlic_instrument_wordpress();
    
    // Track current file
    wpgarlic_track_file(__FILE__);
    
    // Output initialization marker
    fwrite(STDERR, "__COVERAGE_INIT__wpgarlic_coverage_initialized__ENDCOVERAGE__\n");
}

// Auto-initialize if this file is included
if (!defined('WPGARLIC_COVERAGE_INITIALIZED')) {
    define('WPGARLIC_COVERAGE_INITIALIZED', true);
    wpgarlic_init_fuzzing_coverage();
}
?>
