#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Quick APK Analysis Script - Optimized for speed and reliability
Now includes comprehensive massive obfuscation analysis option
"""

import os
import json
import subprocess
import argparse
import sys
import time
import re
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor, TimeoutError

# Set environment variables for better unicode handling on Windows
if sys.platform == "win32":
    os.environ['PYTHONIOENCODING'] = 'utf-8'

def load_sdk_configuration(config_path):
    """
    Load SDK configuration from JSON file
    
    Expected JSON structure:
    {
        "packages": {
            "com.zebra.example": {
                "sdk_classes": [
                    "Lcom/zebra/rfid/",
                    "Lcom/zebra/barcode/",
                    "Lcom/symbol/emdk/"
                ],
                "legitimate_classes": [
                    "Lzebra/",
                    "Lsymbol/"
                ]
            },
            "com.honeywell.example": {
                "sdk_classes": [
                    "Lcom/honeywell/aidc/",
                    "Lcom/intermec/"
                ],
                "legitimate_classes": [
                    "Lhw/",
                    "Laidc/"
                ]
            }
        }
    }
    """
    if not config_path or not os.path.exists(config_path):
        return None
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        # Validate configuration structure
        if 'packages' not in config:
            print(f"Warning: SDK configuration missing 'packages' section")
            return None
        
        # Validate each package configuration
        for package_name, package_config in config['packages'].items():
            if not isinstance(package_config, dict):
                print(f"Warning: Invalid package configuration for {package_name}")
                continue
            
            # Ensure sdk_classes and legitimate_classes are lists
            if 'sdk_classes' in package_config and not isinstance(package_config['sdk_classes'], list):
                print(f"Warning: 'sdk_classes' for {package_name} should be a list")
                package_config['sdk_classes'] = []
            
            if 'legitimate_classes' in package_config and not isinstance(package_config['legitimate_classes'], list):
                print(f"Warning: 'legitimate_classes' for {package_name} should be a list")
                package_config['legitimate_classes'] = []
            
            # Set defaults if missing
            package_config.setdefault('sdk_classes', [])
            package_config.setdefault('legitimate_classes', [])
        
        print(f"✅ Loaded SDK configuration for {len(config['packages'])} packages")
        return config
        
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in SDK configuration file: {e}")
        return None
    except Exception as e:
        print(f"Error: Failed to load SDK configuration: {e}")
        return None

def get_package_sdk_config(package_name, sdk_config):
    """
    Get SDK configuration for a specific package name
    Supports exact match and wildcard matching
    """
    if not sdk_config or 'packages' not in sdk_config:
        return None
    
    packages = sdk_config['packages']
    
    # First try exact match
    if package_name in packages:
        return packages[package_name]
    
    # Try wildcard matching - find the most specific match
    best_match = None
    best_match_length = 0
    
    for config_package, config_data in packages.items():
        # Check if config package is a prefix of the actual package
        if package_name.startswith(config_package):
            if len(config_package) > best_match_length:
                best_match = config_data
                best_match_length = len(config_package)
        # Check if the config package contains wildcards
        elif '*' in config_package:
            # Convert wildcard pattern to regex
            pattern = config_package.replace('*', '.*')
            if re.match(pattern, package_name):
                if len(config_package.replace('*', '')) > best_match_length:
                    best_match = config_data
                    best_match_length = len(config_package.replace('*', ''))
    
    return best_match

def apply_sdk_config_to_comprehensive_test(apk_path, package_name, sdk_config, timeout=45):
    """
    Run comprehensive massive obfuscation test with SDK configuration
    """
    print(f"    Running comprehensive massive obfuscation test with SDK config... (timeout: {timeout}s)")
    start_time = time.time()
    
    try:
        # Get the script directory to find comprehensive_massive_obf_test.py
        script_dir = os.path.dirname(os.path.abspath(__file__))
        comprehensive_script = os.path.join(script_dir, "comprehensive_massive_obf_test.py")
        
        if not os.path.exists(comprehensive_script):
            return {
                'success': False,
                'error': f'comprehensive_massive_obf_test.py not found at {comprehensive_script}',
                'execution_time': 0
            }
        
        # Prepare command arguments
        cmd = [sys.executable, comprehensive_script, apk_path]
        
        # Add SDK configuration if available
        package_config = get_package_sdk_config(package_name, sdk_config)
        if package_config:
            print(f"    📦 Using SDK config for package: {package_name}")
            print(f"    📋 Custom SDK classes: {len(package_config['sdk_classes'])}")
            print(f"    📋 Custom legitimate classes: {len(package_config['legitimate_classes'])}")
            
            # Create temporary config file for the subprocess
            temp_config = {
                'package_name': package_name,
                'sdk_classes': package_config['sdk_classes'],
                'legitimate_classes': package_config['legitimate_classes']
            }
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as temp_file:
                json.dump(temp_config, temp_file, indent=2)
                temp_config_path = temp_file.name
            
            # Add config file argument
            cmd.extend(['--sdk-config', temp_config_path])
        
        # Run the comprehensive analysis
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding='utf-8',
            errors='ignore'  # Ignore Unicode encoding errors
        )
        
        # Clean up temporary config file
        if package_config and 'temp_config_path' in locals():
            try:
                os.unlink(temp_config_path)
            except:
                pass
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        print(f"    Comprehensive test completed in {execution_time:.2f}s, return code: {result.returncode}")
        
        # Parse the output to extract key information
        stdout = result.stdout
        parsed_data = parse_comprehensive_obf_output(stdout)
        
        return {
            'success': True,
            'stdout': stdout,
            'stderr': result.stderr.strip(),
            'return_code': result.returncode,
            'execution_time': execution_time,
            'parsed_analysis': parsed_data,
            'used_sdk_config': package_config is not None,
            'package_config': package_config
        }
        
    except subprocess.TimeoutExpired:
        print(f"    Comprehensive test TIMEOUT after {timeout}s")
        return {
            'success': False,
            'error': f'Comprehensive test timed out after {timeout} seconds',
            'stdout': '',
            'stderr': '',
            'return_code': -1,
            'execution_time': timeout
        }
    except Exception as e:
        print(f"    Comprehensive test ERROR: {e}")
        return {
            'success': False,
            'error': str(e),
            'stdout': '',
            'stderr': '',
            'return_code': -1,
            'execution_time': 0
        }

def parse_apkid_json_output(stdout):
    """Parse APKiD JSON output into structured data"""
    if not stdout:
        return None
    
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as e:
        return {
            'parse_error': f'Failed to parse APKiD JSON output: {e}',
            'raw_output': stdout
        }

def parse_r8_marker_output(stdout):
    """Parse R8 ExtractMarker output and extract JSON marker data"""
    if not stdout:
        return None
    
    # Look for R8 marker pattern: ~~R8{...}
    r8_pattern = r'~~R8\{.*?\}'
    match = re.search(r8_pattern, stdout, re.DOTALL)  # DOTALL to handle multiline JSON
    
    if match:
        marker_str = match.group(0)
        # Extract just the JSON part (remove ~~R8 prefix)
        json_str = marker_str[4:]  # Remove "~~R8" prefix
        try:
            parsed_json = json.loads(json_str)
            parsed_json['marker_type'] = 'R8'  # Add marker type to JSON
            return parsed_json
        except json.JSONDecodeError as e:
            # Try to find a more complete JSON if the regex was too greedy
            # Look for balanced braces
            brace_count = 0
            json_end = -1
            for i, char in enumerate(json_str):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        json_end = i + 1
                        break
            
            if json_end > 0:
                try:
                    complete_json = json_str[:json_end]
                    parsed_json = json.loads(complete_json)
                    parsed_json['marker_type'] = 'R8'
                    return parsed_json
                except json.JSONDecodeError:
                    pass
            
            return {
                'parse_error': f'Failed to parse R8 marker JSON: {e}',
                'raw_marker': marker_str,
                'marker_type': 'R8',
                'json_fragment': json_str[:200] + ('...' if len(json_str) > 200 else '')
            }
    
    # Look for other markers (D8, L8)
    d8_pattern = r'~~D8\{.*?\}'
    l8_pattern = r'~~L8\{.*?\}'
    
    for pattern, marker_type in [(d8_pattern, 'D8'), (l8_pattern, 'L8')]:
        match = re.search(pattern, stdout, re.DOTALL)
        if match:
            marker_str = match.group(0)
            json_str = marker_str[4:]  # Remove "~~D8" or "~~L8" prefix
            try:
                parsed_json = json.loads(json_str)
                parsed_json['marker_type'] = marker_type
                return parsed_json
            except json.JSONDecodeError as e:
                # Try balanced brace parsing for D8/L8 as well
                brace_count = 0
                json_end = -1
                for i, char in enumerate(json_str):
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            json_end = i + 1
                            break
                
                if json_end > 0:
                    try:
                        complete_json = json_str[:json_end]
                        parsed_json = json.loads(complete_json)
                        parsed_json['marker_type'] = marker_type
                        return parsed_json
                    except json.JSONDecodeError:
                        pass
                
                return {
                    'parse_error': f'Failed to parse {marker_type} marker JSON: {e}',
                    'raw_marker': marker_str,
                    'marker_type': marker_type,
                    'json_fragment': json_str[:200] + ('...' if len(json_str) > 200 else '')
                }
    
    # No marker found
    return {
        'marker_found': False,
        'raw_output': stdout[:500] + ('...' if len(stdout) > 500 else '')  # Limit raw output for readability
    }

def run_command_with_timeout(cmd, timeout=10):
    """Run a command with a strict timeout"""
    print(f"    Running: {' '.join(cmd[:3])}... (timeout: {timeout}s)")
    start_time = time.time()
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        end_time = time.time()
        print(f"    Completed in {end_time - start_time:.2f}s, return code: {result.returncode}")
        
        return {
            'success': True,
            'stdout': result.stdout.strip(),  # Remove output size limit to preserve full JSON
            'stderr': result.stderr.strip(),
            'return_code': result.returncode,
            'execution_time': end_time - start_time
        }
    except subprocess.TimeoutExpired:
        print(f"    TIMEOUT after {timeout}s")
        return {
            'success': False,
            'error': f'Command timed out after {timeout} seconds',
            'stdout': '',
            'stderr': '',
            'return_code': -1,
            'execution_time': timeout
        }
    except Exception as e:
        print(f"    ERROR: {e}")
        return {
            'success': False,
            'error': str(e),
            'stdout': '',
            'stderr': '',
            'return_code': -1,
            'execution_time': 0
        }

def run_comprehensive_massive_obf_test(apk_path, timeout=30, package_name=None, sdk_config=None):
    """
    Run comprehensive massive obfuscation test and return structured results
    """
    # Use the enhanced version if SDK config is available
    if sdk_config and package_name:
        return apply_sdk_config_to_comprehensive_test(apk_path, package_name, sdk_config, timeout)
    
    # Fallback to original implementation
    print(f"    Running comprehensive massive obfuscation test... (timeout: {timeout}s)")
    start_time = time.time()
    
    try:
        # Get the script directory to find comprehensive_massive_obf_test.py
        script_dir = os.path.dirname(os.path.abspath(__file__))
        comprehensive_script = os.path.join(script_dir, "comprehensive_massive_obf_test.py")
        
        if not os.path.exists(comprehensive_script):
            return {
                'success': False,
                'error': f'comprehensive_massive_obf_test.py not found at {comprehensive_script}',
                'execution_time': 0
            }
        
        # Run the comprehensive analysis
        result = subprocess.run(
            [sys.executable, comprehensive_script, apk_path],
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding='utf-8',
            errors='ignore'  # Ignore Unicode encoding errors
        )
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        print(f"    Comprehensive test completed in {execution_time:.2f}s, return code: {result.returncode}")
        
        # Parse the output to extract key information
        stdout = result.stdout
        parsed_data = parse_comprehensive_obf_output(stdout)
        
        return {
            'success': True,
            'stdout': stdout,
            'stderr': result.stderr.strip(),
            'return_code': result.returncode,
            'execution_time': execution_time,
            'parsed_analysis': parsed_data
        }
        
    except subprocess.TimeoutExpired:
        print(f"    Comprehensive test TIMEOUT after {timeout}s")
        return {
            'success': False,
            'error': f'Comprehensive test timed out after {timeout} seconds',
            'stdout': '',
            'stderr': '',
            'return_code': -1,
            'execution_time': timeout
        }
    except Exception as e:
        print(f"    Comprehensive test ERROR: {e}")
        return {
            'success': False,
            'error': str(e),
            'stdout': '',
            'stderr': '',
            'return_code': -1,
            'execution_time': 0
        }

def parse_comprehensive_obf_output(stdout):
    """
    Parse comprehensive obfuscation test output into structured data with dual analysis support
    
    New enhanced format includes:
    - detailed_results: List of individual DEX file analyses, each containing:
      * Basic info (dex_name, dex_size_bytes, total_classes, etc.)
      * dual_analysis section with:
        - yara_strict: YARA rule detection results and methods passed
        - manual_inspection: Manual analysis results and broader detection
        - effectiveness_gap: Comparison ratios and agreement status
    
    - final_dual_analysis: Aggregated summary across all DEX files containing:
      * aggregated_analysis: Combined totals from all DEX files
      * apk_level_decision: Final APK-level triggering decision
      * per_dex_summary: Quick overview of each DEX file's results
      * method_summary: Which methods passed in how many DEX files
    
    This provides comprehensive insight into both YARA rule limitations
    and the effectiveness gap between strict pattern matching and manual inspection.
    """
    if not stdout:
        return None
    
    try:
        # Extract key metrics from the output
        data = {
            'apkid_detected_massive_obf': False,
            'dex_files_analyzed': 0,
            'highest_completion_percentage': 0.0,
            'manual_analysis_result': 'NOT_TRIGGERED',
            'consistency_check': 'UNKNOWN',
            'analysis_type': 'UNKNOWN',  # MULTI_DEX_COMBINED, SINGLE_DEX, or FALLBACK
            'dex_modality': 'UNKNOWN',   # single_dex, multi_dex, small_dex
            'rule_system_used': 'UNKNOWN',  # CONFIGURABLE_RULES or LEGACY
            'detailed_results': []
        }
        
        # Detect analysis type
        if 'MULTI-DEX COMBINED ANALYSIS' in stdout:
            data['analysis_type'] = 'MULTI_DEX_COMBINED'
        elif 'SINGLE DEX ANALYSIS' in stdout:
            data['analysis_type'] = 'SINGLE_DEX'
        else:
            data['analysis_type'] = 'FALLBACK'
        
        # Extract DEX modality
        import re
        modality_match = re.search(r'DEX Modality:\s*(\w+)', stdout)
        if modality_match:
            data['dex_modality'] = modality_match.group(1)
        
        # Detect rule system used
        if 'CONFIGURABLE RULE-BASED ANALYSIS' in stdout or 'COMBINED MULTI-DEX RULE EVALUATION' in stdout:
            data['rule_system_used'] = 'CONFIGURABLE_RULES'
        else:
            data['rule_system_used'] = 'LEGACY'
        
        # Look for APKiD results
        if 'massive_name_obfuscation: 🔴 DETECTED' in stdout or 'massive_name_obfuscation: DETECTED' in stdout:
            data['apkid_detected_massive_obf'] = True
        elif 'massive_name_obfuscation: 🟢 NOT DETECTED' in stdout or 'massive_name_obfuscation: NOT DETECTED' in stdout:
            data['apkid_detected_massive_obf'] = False
        
        # Extract completion percentage from new format
        # New format: "Best completion: X.X%" or "Highest completion percentage: X.X%"
        percentage_patterns = [
            r'Best completion:\s*(\d+\.?\d*)%',
            r'Highest completion percentage:\s*(\d+\.?\d*)%',
            r'Completion percentage:\s*(\d+\.?\d*)%'
        ]
        
        for pattern in percentage_patterns:
            percentages = re.findall(pattern, stdout)
            if percentages:
                data['highest_completion_percentage'] = float(percentages[-1])  # Use last match
                break
        
        # Extract manual analysis result from new format
        if 'Manual analysis result: 🔴 SHOULD NOT TRIGGER' in stdout or 'SHOULD NOT TRIGGER' in stdout:
            data['manual_analysis_result'] = 'SHOULD_NOT_TRIGGER'
        elif 'Manual analysis result: � SHOULD TRIGGER' in stdout or 'SHOULD TRIGGER' in stdout:
            data['manual_analysis_result'] = 'SHOULD_TRIGGER'
        
        # Extract consistency check from new format
        if 'Consistency: ✅ Manual analysis matches APKiD result' in stdout or 'Manual analysis matches APKiD' in stdout:
            data['consistency_check'] = 'CONSISTENT'
        elif 'Consistency: ⚠️ Manual analysis differs from APKiD result' in stdout or 'differs from APKiD' in stdout:
            data['consistency_check'] = 'INCONSISTENT'
        
        # Count DEX files analyzed from new format
        dex_count_patterns = [
            r'Files analyzed:\s*(\d+)\s*DEX',
            r'Total DEX files:\s*(\d+)',
            r'(\d+)\s*DEX files'
        ]
        
        for pattern in dex_count_patterns:
            dex_matches = re.findall(pattern, stdout)
            if dex_matches:
                data['dex_files_analyzed'] = int(dex_matches[-1])  # Use last match
                break
        
        # Parse new configurable rules analysis results
        if data['rule_system_used'] == 'CONFIGURABLE_RULES':
            data.update(parse_configurable_rules_results(stdout))
        else:
            # Fallback to legacy parsing for backward compatibility
            data.update(parse_legacy_method_results(stdout))
        
        # Extract individual DEX analysis results for detailed_results
        data['detailed_results'] = extract_individual_dex_analysis(stdout)
        
        # Create final_dual_analysis by aggregating all DEX results
        data['final_dual_analysis'] = create_final_dual_analysis(data['detailed_results'], data.get('dex_files_analyzed', 0))
        
        return data
        
    except Exception as e:
        print(f"Error parsing comprehensive massive obfuscation output: {e}")
        return {
            'apkid_detected_massive_obf': False,
            'dex_files_analyzed': 0,
            'highest_completion_percentage': 0.0,
            'manual_analysis_result': 'ERROR',
            'consistency_check': 'ERROR',
            'analysis_type': 'ERROR',
            'dex_modality': 'ERROR',
            'rule_system_used': 'ERROR',
            'detailed_results': []
        }

def parse_configurable_rules_results(stdout):
    """Parse results from the new configurable rules system"""
    import re
    results = {}
    
    # Extract rule evaluation results
    rule_results = []
    
    # Look for rule evaluation sections
    rule_pattern = r'Rule "([^"]+)":\s*(.*?)(?=Rule "|$)'
    rule_matches = re.findall(rule_pattern, stdout, re.DOTALL)
    
    for rule_name, rule_content in rule_matches:
        rule_result = {
            'rule_name': rule_name,
            'triggered': False,
            'details': {}
        }
        
        # Check if rule triggered
        if 'TRIGGERED' in rule_content or '🔴' in rule_content:
            rule_result['triggered'] = True
        elif 'NOT TRIGGERED' in rule_content or '🟢' in rule_content:
            rule_result['triggered'] = False
        
        # Extract specific details for each rule type
        if 'min_unique_string_short' in rule_content:
            match = re.search(r'min_unique_string_short:\s*(\d+)', rule_content)
            if match:
                rule_result['details']['min_unique_string_short'] = int(match.group(1))
        
        if 'min_total_short_strings' in rule_content:
            match = re.search(r'min_total_short_strings:\s*(\d+)', rule_content)
            if match:
                rule_result['details']['min_total_short_strings'] = int(match.group(1))
        
        rule_results.append(rule_result)
    
    results['configurable_rules'] = rule_results
    
    # Extract combined metrics if available
    combined_patterns = {
        'total_classes': r'Combined total classes:\s*(\d+)',
        'unique_short_strings': r'Combined unique short strings:\s*(\d+)',
        'total_short_strings': r'Combined total short strings:\s*(\d+)',
        'unique_very_short_strings': r'Combined unique very short strings:\s*(\d+)',
        'total_very_short_strings': r'Combined total very short strings:\s*(\d+)'
    }
    
    for metric, pattern in combined_patterns.items():
        match = re.search(pattern, stdout)
        if match:
            results[metric] = int(match.group(1))
    
    return results

def parse_legacy_method_results(stdout):
    """Parse results from legacy Method 1-5 system for backward compatibility"""
    import re
    results = {}
    
    # Look for Method sections
    method_sections = re.findall(r'(Method \d+[^:]*:.*?)(?=Method \d+|$)', stdout, re.DOTALL)
    
    legacy_results = []
    for section in method_sections:
        method_result = {
            'method_name': 'Unknown',
            'triggered': False,
            'details': {}
        }
        
        # Extract method name
        method_match = re.search(r'(Method \d+[^:]*)', section)
        if method_match:
            method_result['method_name'] = method_match.group(1)
        
        # Check if triggered
        if 'TRIGGERED' in section or '🔴' in section:
            method_result['triggered'] = True
        elif 'NOT TRIGGERED' in section or '🟢' in section:
            method_result['triggered'] = False
        
        legacy_results.append(method_result)
    
    results['legacy_methods'] = legacy_results
    
    # Look for YARA-STRICT vs MANUAL comparison
    if 'YARA-STRICT vs MANUAL ANALYSIS' in stdout:
        comparison_section = stdout.split('YARA-STRICT vs MANUAL ANALYSIS')[1]
        
        # Extract comparison results
        if 'Agreement: ✅ CONSISTENT' in comparison_section:
            results['yara_manual_agreement'] = 'CONSISTENT'
        elif 'Agreement: ⚠️ DIFFERENT' in comparison_section:
            results['yara_manual_agreement'] = 'INCONSISTENT'
    
    return results

def extract_individual_dex_analysis(stdout):
    """
    Extract individual DEX analysis results with dual analysis data
    Returns array of DEX analyses including yara_strict and manual_inspection for each DEX
    """
    dex_results = []
    
    # Split the output by DETAILED ANALYSIS sections
    if 'DETAILED ANALYSIS:' in stdout:
        # Split by the detailed analysis marker
        sections = stdout.split('DETAILED ANALYSIS:')
        
        for i, section in enumerate(sections[1:], 1):  # Skip first empty section
            # Parse this individual DEX section
            dex_result = parse_individual_dex_result(section)
            
            # Only include if we successfully parsed basic info
            if dex_result.get('dex_name', 'unknown') != 'unknown':
                # Format the result to match the desired structure
                formatted_result = {
                    "dex_name": dex_result['dex_name'],
                    "dex_size_bytes": dex_result['dex_size_bytes'],
                    "dual_analysis": {
                        "yara_strict": {
                            "total_classes": dex_result['dual_analysis']['yara_strict']['total_classes'],
                            "logical_classes": dex_result['dual_analysis']['yara_strict']['logical_classes'],
                            "short_strings": dex_result['dual_analysis']['yara_strict']['short_strings'],
                            "single_classes": dex_result['dual_analysis']['yara_strict']['single_classes'],
                            "two_digit_classes": dex_result['dual_analysis']['yara_strict']['two_digit_classes'],
                            "three_char_classes": dex_result['dual_analysis']['yara_strict']['three_char_classes'],
                            "single_methods": dex_result['dual_analysis']['yara_strict']['single_methods']
                        },
                        "manual_inspection": {
                            "total_classes": dex_result['dual_analysis']['manual_inspection']['total_classes'],
                            "logical_classes": dex_result['dual_analysis']['manual_inspection']['logical_classes'],
                            "non_discovered_sdk_classes": dex_result['dual_analysis']['manual_inspection']['non_discovered_sdk_classes'],
                            "zebra_symbol_classes": dex_result['dual_analysis']['manual_inspection']['zebra_symbol_classes'],
                            "short_strings": dex_result['dual_analysis']['manual_inspection']['short_strings'],
                            "single_classes": dex_result['dual_analysis']['manual_inspection']['single_classes'],
                            "two_digit_classes": dex_result['dual_analysis']['manual_inspection']['two_digit_classes'],
                            "three_char_classes": dex_result['dual_analysis']['manual_inspection']['three_char_classes'],
                            "single_methods": dex_result['dual_analysis']['manual_inspection']['single_methods']
                        }
                    }
                }
                dex_results.append(formatted_result)
    
    return dex_results

def create_final_dual_analysis(detailed_results, total_dex_count):
    """
    Create aggregated final dual analysis from individual DEX results
    Sums up all metrics from individual DEX files
    """
    if not detailed_results:
        return {
            "total_dex_files": total_dex_count,
            "aggregated_analysis": {
                "yara_strict": {
                    "total_classes": 0,
                    "logical_classes": 0,
                    "short_strings": 0,
                    "single_classes": 0,
                    "two_digit_classes": 0,
                    "three_char_classes": 0,
                    "single_methods": 0
                },
                "manual_inspection": {
                    "total_classes": 0,
                    "logical_classes": 0,
                    "non_discovered_sdk_classes": 0,
                    "zebra_symbol_classes": 0,
                    "short_strings": 0,
                    "single_classes": 0,
                    "two_digit_classes": 0,
                    "three_char_classes": 0,
                    "single_methods": 0
                }
            }
        }
    
    # Initialize aggregated totals
    yara_totals = {
        "total_classes": 0,
        "logical_classes": 0,
        "short_strings": 0,
        "single_classes": 0,
        "two_digit_classes": 0,
        "three_char_classes": 0,
        "single_methods": 0
    }
    
    manual_totals = {
        "total_classes": 0,
        "logical_classes": 0,
        "non_discovered_sdk_classes": 0,
        "zebra_symbol_classes": 0,
        "short_strings": 0,
        "single_classes": 0,
        "two_digit_classes": 0,
        "three_char_classes": 0,
        "single_methods": 0
    }
    
    # Sum up all DEX file results
    for dex_result in detailed_results:
        yara = dex_result['dual_analysis']['yara_strict']
        manual = dex_result['dual_analysis']['manual_inspection']
        
        # Sum YARA metrics
        yara_totals["total_classes"] += yara.get("total_classes", 0)
        yara_totals["logical_classes"] += yara.get("logical_classes", 0)
        yara_totals["short_strings"] += yara.get("short_strings", 0)
        yara_totals["single_classes"] += yara.get("single_classes", 0)
        yara_totals["two_digit_classes"] += yara.get("two_digit_classes", 0)
        yara_totals["three_char_classes"] += yara.get("three_char_classes", 0)
        yara_totals["single_methods"] += yara.get("single_methods", 0)
        
        # Sum manual inspection metrics
        manual_totals["total_classes"] += manual.get("total_classes", 0)
        manual_totals["logical_classes"] += manual.get("logical_classes", 0)
        manual_totals["non_discovered_sdk_classes"] += manual.get("non_discovered_sdk_classes", 0)
        manual_totals["zebra_symbol_classes"] += manual.get("zebra_symbol_classes", 0)
        manual_totals["short_strings"] += manual.get("short_strings", 0)
        manual_totals["single_classes"] += manual.get("single_classes", 0)
        manual_totals["two_digit_classes"] += manual.get("two_digit_classes", 0)
        manual_totals["three_char_classes"] += manual.get("three_char_classes", 0)
        manual_totals["single_methods"] += manual.get("single_methods", 0)
    
    return {
        "total_dex_files": len(detailed_results),
        "aggregated_analysis": {
            "yara_strict": {
                "total_classes": yara_totals["total_classes"],
                "logical_classes": yara_totals["logical_classes"],
                "short_strings": yara_totals["short_strings"],
                "single_classes": yara_totals["single_classes"],
                "two_digit_classes": yara_totals["two_digit_classes"],
                "three_char_classes": yara_totals["three_char_classes"],
                "single_methods": yara_totals["single_methods"]
            },
            "manual_inspection": {
                "total_classes": manual_totals["total_classes"],
                "logical_classes": manual_totals["logical_classes"],
                "non_discovered_sdk_classes": manual_totals["non_discovered_sdk_classes"],
                "zebra_symbol_classes": manual_totals["zebra_symbol_classes"],
                "short_strings": manual_totals["short_strings"],
                "single_classes": manual_totals["single_classes"],
                "two_digit_classes": manual_totals["two_digit_classes"],
                "three_char_classes": manual_totals["three_char_classes"],
                "single_methods": manual_totals["single_methods"]
            }
        }
    }

def extract_combined_analysis_section(stdout):
    """Extract the combined analysis section from comprehensive test output"""
    import re
    
    combined_analysis = {
        'section_found': False,
        'analysis_type': 'UNKNOWN',
        'total_dex_files': 0,
        'combined_metrics': {},
        'rule_evaluations': [],
        'pattern_aggregation': {},
        'raw_section': ''
    }
    
    # Look for MULTI-DEX COMBINED ANALYSIS section
    multi_dex_pattern = r'MULTI-DEX COMBINED ANALYSIS.*?(?=================================================================================|$)'
    multi_dex_match = re.search(multi_dex_pattern, stdout, re.DOTALL)
    
    if multi_dex_match:
        combined_analysis['section_found'] = True
        combined_analysis['analysis_type'] = 'MULTI_DEX_COMBINED'
        section_content = multi_dex_match.group(0)
        combined_analysis['raw_section'] = section_content
        
        # Extract DEX file count
        dex_count_match = re.search(r'(\d+)\s*DEX files?', section_content)
        if dex_count_match:
            combined_analysis['total_dex_files'] = int(dex_count_match.group(1))
        
        # Extract combined metrics
        metrics_patterns = {
            'total_classes': r'Combined total classes:\s*(\d+(?:,\d+)*)',
            'unique_short_strings': r'Combined unique short strings:\s*(\d+(?:,\d+)*)',
            'total_short_strings': r'Combined total short strings:\s*(\d+(?:,\d+)*)',
            'unique_very_short_strings': r'Combined unique very short strings:\s*(\d+(?:,\d+)*)',
            'total_very_short_strings': r'Combined total very short strings:\s*(\d+(?:,\d+)*)',
            'logical_classes': r'Logical classes:\s*(\d+(?:,\d+)*)',
            'sdk_classes': r'SDK classes:\s*(\d+(?:,\d+)*)',
            'single_methods': r'Single methods:\s*(\d+(?:,\d+)*)',
            'two_char_classes': r'Two-char classes:\s*(\d+(?:,\d+)*)',
            'three_char_classes': r'Three-char classes:\s*(\d+(?:,\d+)*)'
        }
        
        for metric, pattern in metrics_patterns.items():
            match = re.search(pattern, section_content)
            if match:
                # Remove commas and convert to int
                value = int(match.group(1).replace(',', ''))
                combined_analysis['combined_metrics'][metric] = value
        
        # Extract rule evaluation results
        rule_pattern = r'Rule "([^"]+)":(.*?)(?=Rule "|$)'
        rule_matches = re.findall(rule_pattern, section_content, re.DOTALL)
        
        for rule_name, rule_content in rule_matches:
            rule_eval = {
                'rule_name': rule_name,
                'triggered': False,
                'conditions': [],
                'result_details': rule_content.strip()
            }
            
            # Check if triggered
            if 'TRIGGERED' in rule_content or '🔴' in rule_content:
                rule_eval['triggered'] = True
            elif 'NOT TRIGGERED' in rule_content or '🟢' in rule_content:
                rule_eval['triggered'] = False
            
            # Extract condition details
            condition_patterns = {
                'min_unique_string_short': r'min_unique_string_short:\s*(\d+)',
                'min_total_short_strings': r'min_total_short_strings:\s*(\d+)',
                'min_classes': r'min_classes:\s*(\d+)',
                'min_methods': r'min_methods:\s*(\d+)'
            }
            
            for condition, pattern in condition_patterns.items():
                match = re.search(pattern, rule_content)
                if match:
                    threshold = int(match.group(1))
                    
                    # Try to find current value
                    current_match = re.search(rf'{condition}:\s*\d+\s*\(current:\s*(\d+)\)', rule_content)
                    if current_match:
                        current_value = int(current_match.group(1))
                        rule_eval['conditions'].append({
                            'condition': condition,
                            'threshold': threshold,
                            'current_value': current_value,
                            'passed': current_value >= threshold
                        })
            
            combined_analysis['rule_evaluations'].append(rule_eval)
    
    # Look for SINGLE DEX ANALYSIS as fallback
    elif 'SINGLE DEX ANALYSIS' in stdout:
        combined_analysis['section_found'] = True
        combined_analysis['analysis_type'] = 'SINGLE_DEX'
        combined_analysis['total_dex_files'] = 1
    
    return combined_analysis

def extract_detailed_analysis_section(stdout):
    """Extract detailed analysis sections for individual DEX files"""
    import re
    
    detailed_analysis = {
        'dex_files': [],
        'total_dex_analyzed': 0,
        'analysis_method': 'UNKNOWN'
    }
    
    # For new combined analysis, look for pattern extraction sections
    if 'MULTI-DEX COMBINED ANALYSIS' in stdout:
        detailed_analysis['analysis_method'] = 'COMBINED_MULTI_DEX'
        
        # Extract individual DEX pattern extraction
        dex_pattern = r'Extracting patterns from:\s*([^\\n]+)(.*?)(?=Extracting patterns from:|COMBINED MULTI-DEX|$)'
        dex_matches = re.findall(dex_pattern, stdout, re.DOTALL)
        
        for dex_name, dex_content in dex_matches:
            dex_info = {
                'dex_name': dex_name.strip(),
                'dex_size_bytes': 0,
                'header_classes': 0,
                'patterns_extracted': {},
                'raw_analysis': dex_content.strip()
            }
            
            # Extract DEX size
            size_match = re.search(r'DEX file size:\s*([0-9,]+)\s*bytes', dex_content)
            if size_match:
                dex_info['dex_size_bytes'] = int(size_match.group(1).replace(',', ''))
            
            # Extract header class count
            header_match = re.search(r'DEX header class_defs_size:\s*([0-9,]+)', dex_content)
            if header_match:
                dex_info['header_classes'] = int(header_match.group(1).replace(',', ''))
            
            # Extract patterns extracted info
            patterns_match = re.search(r'Extracted patterns:\s*YARA=(\d+)\s*fields,\s*Manual=(\d+)\s*fields', dex_content)
            if patterns_match:
                dex_info['patterns_extracted'] = {
                    'yara_fields': int(patterns_match.group(1)),
                    'manual_fields': int(patterns_match.group(2))
                }
            
            detailed_analysis['dex_files'].append(dex_info)
        
        detailed_analysis['total_dex_analyzed'] = len(detailed_analysis['dex_files'])
    
    # For legacy detailed analysis, look for individual DEX analysis sections
    elif 'DETAILED ANALYSIS:' in stdout:
        detailed_analysis['analysis_method'] = 'INDIVIDUAL_DEX_LEGACY'
        
        # Split by detailed analysis markers
        dex_sections = stdout.split('DETAILED ANALYSIS:')
        
        for i, section in enumerate(dex_sections[1:], 1):  # Skip first empty section
            dex_info = {
                'dex_number': i,
                'analysis_content': section[:1000] + ('...' if len(section) > 1000 else ''),  # Truncate for size
                'has_dual_analysis': 'YARA-STRICT vs MANUAL' in section,
                'has_method_comparison': 'Method ' in section
            }
            
            # Extract basic info
            name_match = re.search(r'(\w+\.dex)', section)
            if name_match:
                dex_info['dex_name'] = name_match.group(1)
            
            size_match = re.search(r'DEX file size:\s*([0-9,]+)', section)
            if size_match:
                dex_info['dex_size_bytes'] = int(size_match.group(1).replace(',', ''))
            
            classes_match = re.search(r'Total classes.*?:\s*([0-9,]+)', section)
            if classes_match:
                dex_info['total_classes'] = int(classes_match.group(1).replace(',', ''))
            
            detailed_analysis['dex_files'].append(dex_info)
        
        detailed_analysis['total_dex_analyzed'] = len(detailed_analysis['dex_files'])
    
    return detailed_analysis

def parse_individual_dex_result(section):
    """Parse individual DEX analysis section with comprehensive dual analysis
    
    CRITICAL BUG FIX (2025-07-30): 
    Fixed logical_classes > total_classes anomaly that affected 25.32% of DEX files.
    
    Root Cause: The parsing logic incorrectly used YARA pattern count "Total classes (L...;)" 
    as the total classes, but "Logical classes" is calculated from DEX header classes.
    This caused mathematical impossibility where logical > total in 118/466 DEX files.
    
    Solution: Use "DEX header classes" as the true total count, and cap logical classes
    to ensure data integrity: logical_classes <= total_classes
    
    Console Output Format:
    - Total classes (L...;): X      <- YARA regex pattern matches 
    - DEX header classes: Y         <- Actual DEX file class count (use as total)
    - Logical classes: Z            <- Calculated value (should be <= Y)
    """
    try:
        result = {
            'dex_name': 'unknown',
            'dex_size_bytes': 0,
            'total_classes': 0,
            'logical_classes': 0,
            'conditions_passed': 0,
            'total_conditions': 0,
            'completion_percentage': 0.0,
            'should_trigger': False,
            'methods_passed': [],
            'methods_failed': [],
            'method_details': {},
            'dual_analysis': {
                'yara_strict': {
                    'total_classes': 0,
                    'logical_classes': 0,
                    'short_strings': 0,
                    'single_classes': 0,
                    'two_digit_classes': 0,
                    'three_char_classes': 0,
                    'single_methods': 0,
                    'methods_passed': [],
                    'methods_failed': [],
                    'methods_passed_count': 0,
                    'should_trigger': False,
                    'method_details': {}
                },
                'manual_inspection': {
                    'total_classes': 0,
                    'logical_classes': 0,
                    'non_discovered_sdk_classes': 0,
                    'zebra_symbol_classes': 0,
                    'short_strings': 0,
                    'single_classes': 0,
                    'two_digit_classes': 0,
                    'three_char_classes': 0,
                    'single_methods': 0,
                    'methods_passed': [],
                    'methods_failed': [],
                    'methods_passed_count': 0,
                    'should_trigger': False,
                    'method_details': {}
                },
                'effectiveness_gap': {
                    'short_strings_ratio': 0.0,
                    'single_classes_ratio': 0.0,
                    'two_digit_ratio': 0.0,
                    'three_char_ratio': 0.0,
                    'single_method_ratio': 0.0,
                    'methods_gap': 0,
                    'agreement': 'UNKNOWN'
                }
            }
        }
        
        # Extract DEX name
        name_match = re.search(r'(\w+\.dex)', section)
        if name_match:
            result['dex_name'] = name_match.group(1)
        
        # Extract DEX size
        size_match = re.search(r'DEX file size:\s*([0-9,]+)\s*bytes', section)
        if size_match:
            result['dex_size_bytes'] = int(size_match.group(1).replace(',', ''))
        
        # Extract Zebra/Symbol classes from main analysis section (before YARA-STRICT)
        main_analysis_section = re.search(r'📊 Manual analysis - using zebra_sdk_discovery\.py logic:(.*?)📈 Raw Pattern Counts:', section, re.DOTALL)
        if main_analysis_section:
            main_data = main_analysis_section.group(1)
            
            # Extract Zebra/Symbol classes count from main section
            main_zebra_symbol_match = re.search(r'Zebra/Symbol classes:\s*([0-9,]+)', main_data)
            if main_zebra_symbol_match:
                zebra_symbol_count = int(main_zebra_symbol_match.group(1).replace(',', ''))
                # Store this for later use in manual inspection section
                result['_main_zebra_symbol_classes'] = zebra_symbol_count
            
            # Extract non-discovered SDK classes from main section
            main_non_discovered_match = re.search(r'Non-discovered SDK classes:\s*([0-9,]+)', main_data)
            if main_non_discovered_match:
                non_discovered_count = int(main_non_discovered_match.group(1).replace(',', ''))
                result['_main_non_discovered_sdk_classes'] = non_discovered_count
        
        # Extract YARA-STRICT Analysis data
        yara_section = re.search(r'📊 YARA-STRICT Analysis.*?───────────────────────────────────────────────(.*?)📋 MANUAL INSPECTION Analysis', section, re.DOTALL)
        if yara_section:
            yara_data = yara_section.group(1)
            
            # Extract YARA counts - IMPORTANT: Use DEX header classes as total, not YARA pattern count
            yara_pattern_count_match = re.search(r'Total classes \(L\.\.\.;\):\s*([0-9,]+)', yara_data)
            yara_dex_header_match = re.search(r'DEX header classes:\s*([0-9,]+)', yara_data)
            yara_logical_match = re.search(r'Logical classes:\s*([0-9,]+)', yara_data)
            
            # Use DEX header classes as the true total count, not the YARA pattern count
            if yara_dex_header_match:
                result['dual_analysis']['yara_strict']['total_classes'] = int(yara_dex_header_match.group(1).replace(',', ''))
            elif yara_pattern_count_match:
                # Fallback to pattern count if DEX header not available
                result['dual_analysis']['yara_strict']['total_classes'] = int(yara_pattern_count_match.group(1).replace(',', ''))
            
            if yara_logical_match:
                # Logical classes can be negative due to calculation errors in the source
                logical_classes = int(yara_logical_match.group(1).replace(',', ''))
                # Ensure logical classes don't exceed total classes (data integrity fix)
                total_classes = result['dual_analysis']['yara_strict']['total_classes']
                if logical_classes > total_classes and total_classes > 0:
                    # Log this anomaly but cap logical classes to total classes
                    result['dual_analysis']['yara_strict']['logical_classes'] = total_classes
                    result['dual_analysis']['yara_strict']['_logical_anomaly'] = {
                        'original_logical': logical_classes,
                        'capped_to_total': total_classes,
                        'anomaly_type': 'logical_exceeds_total'
                    }
                else:
                    result['dual_analysis']['yara_strict']['logical_classes'] = max(0, logical_classes)  # Ensure non-negative
            
            yara_short_strings_match = re.search(r'Short strings \(a-e\):\s*([0-9,]+)', yara_data)
            if yara_short_strings_match:
                result['dual_analysis']['yara_strict']['short_strings'] = int(yara_short_strings_match.group(1).replace(',', ''))
            
            yara_single_classes_match = re.search(r'Single class names:\s*([0-9,]+)', yara_data)
            if yara_single_classes_match:
                result['dual_analysis']['yara_strict']['single_classes'] = int(yara_single_classes_match.group(1).replace(',', ''))
            
            yara_two_char_match = re.search(r'Two-char classes:\s*([0-9,]+)', yara_data)
            if yara_two_char_match:
                result['dual_analysis']['yara_strict']['two_digit_classes'] = int(yara_two_char_match.group(1).replace(',', ''))
            
            yara_three_char_match = re.search(r'Three-char classes:\s*([0-9,]+)', yara_data)
            if yara_three_char_match:
                result['dual_analysis']['yara_strict']['three_char_classes'] = int(yara_three_char_match.group(1).replace(',', ''))
            
            yara_methods_match = re.search(r'Single methods:\s*([0-9,]+)', yara_data)
            if yara_methods_match:
                result['dual_analysis']['yara_strict']['single_methods'] = int(yara_methods_match.group(1).replace(',', ''))
            
            # Extract YARA methods passed - look in the comparison section instead
            yara_methods_passed = []
            yara_methods_failed = []
            
            # Extract YARA should trigger
            if 'Rule should trigger: 🔴 YES' in yara_data:
                result['dual_analysis']['yara_strict']['should_trigger'] = True
            elif 'Rule should trigger: 🟢 NO' in yara_data:
                result['dual_analysis']['yara_strict']['should_trigger'] = False
        
        # Extract MANUAL INSPECTION Analysis data
        manual_section = re.search(r'📋 MANUAL INSPECTION Analysis.*?───────────────────────────────────────────────(.*?)🔍 COMPARISON', section, re.DOTALL)
        if manual_section:
            manual_data = manual_section.group(1)
            
            # Extract manual counts
            manual_total_match = re.search(r'Total unique classes:\s*([0-9,]+)', manual_data)
            if manual_total_match:
                result['dual_analysis']['manual_inspection']['total_classes'] = int(manual_total_match.group(1).replace(',', ''))
            
            manual_logical_match = re.search(r'Logical classes analyzed:\s*([0-9,]+)', manual_data)
            if manual_logical_match:
                result['dual_analysis']['manual_inspection']['logical_classes'] = int(manual_logical_match.group(1).replace(',', ''))
            
            # Extract non-discovered SDK classes count
            manual_non_discovered_match = re.search(r'Non-discovered SDK classes:\s*([0-9,]+)', manual_data)
            if manual_non_discovered_match:
                result['dual_analysis']['manual_inspection']['non_discovered_sdk_classes'] = int(manual_non_discovered_match.group(1).replace(',', ''))
            elif '_main_non_discovered_sdk_classes' in result:
                # Use value from main analysis section if not found in manual section
                result['dual_analysis']['manual_inspection']['non_discovered_sdk_classes'] = result['_main_non_discovered_sdk_classes']
            
            # Extract Zebra/Symbol classes count
            manual_zebra_symbol_match = re.search(r'Zebra/Symbol classes:\s*([0-9,]+)', manual_data)
            if manual_zebra_symbol_match:
                result['dual_analysis']['manual_inspection']['zebra_symbol_classes'] = int(manual_zebra_symbol_match.group(1).replace(',', ''))
            elif '_main_zebra_symbol_classes' in result:
                # Use value from main analysis section if not found in manual section
                result['dual_analysis']['manual_inspection']['zebra_symbol_classes'] = result['_main_zebra_symbol_classes']
            
            manual_short_strings_match = re.search(r'Short strings \(a-e\):\s*([0-9,]+)', manual_data)
            if manual_short_strings_match:
                result['dual_analysis']['manual_inspection']['short_strings'] = int(manual_short_strings_match.group(1).replace(',', ''))
            
            manual_single_classes_match = re.search(r'Single-digit classes:\s*([0-9,]+)', manual_data)
            if manual_single_classes_match:
                result['dual_analysis']['manual_inspection']['single_classes'] = int(manual_single_classes_match.group(1).replace(',', ''))
            
            manual_two_char_match = re.search(r'Two-digit classes:\s*([0-9,]+)', manual_data)
            if manual_two_char_match:
                result['dual_analysis']['manual_inspection']['two_digit_classes'] = int(manual_two_char_match.group(1).replace(',', ''))
            
            manual_three_char_match = re.search(r'Three-digit classes:\s*([0-9,]+)', manual_data)
            if manual_three_char_match:
                result['dual_analysis']['manual_inspection']['three_char_classes'] = int(manual_three_char_match.group(1).replace(',', ''))
            
            manual_methods_match = re.search(r'Single-char methods:\s*([0-9,]+)', manual_data)
            if manual_methods_match:
                result['dual_analysis']['manual_inspection']['single_methods'] = int(manual_methods_match.group(1).replace(',', ''))
            
            # Extract manual methods passed (look for manual analysis trigger logic)
            manual_methods_passed = []
            manual_methods_failed = []
            
            # Check if manual analysis would pass each method based on the same criteria
            # Note: Manual analysis uses broader patterns, so we need to check the "Rule would trigger" section
            if 'Rule would trigger: 🔴 YES' in manual_data:
                result['dual_analysis']['manual_inspection']['should_trigger'] = True
                # If manual triggers, we assume it passed more methods than YARA
                # We'll extract the specific method details from the comparison section
            elif 'Rule would trigger: 🟢 NO' in manual_data:
                result['dual_analysis']['manual_inspection']['should_trigger'] = False
        
        # Extract effectiveness gap data
        comparison_section = re.search(r'🔍 COMPARISON.*?───────────────────────────────────────(.*?)🎯 Detailed Condition', section, re.DOTALL)
        if comparison_section:
            comparison_data = comparison_section.group(1)
            
            # Extract all pattern ratios
            short_strings_ratio_match = re.search(r'Short strings \(a-e\):.*?vs.*?\(([0-9.]+x|infx)\)', comparison_data)
            if short_strings_ratio_match:
                ratio_str = short_strings_ratio_match.group(1)
                if ratio_str == 'infx':
                    result['dual_analysis']['effectiveness_gap']['short_strings_ratio'] = float('inf')
                else:
                    result['dual_analysis']['effectiveness_gap']['short_strings_ratio'] = float(ratio_str.replace('x', ''))
            
            single_classes_ratio_match = re.search(r'Single classes:.*?vs.*?\(([0-9.]+x|infx)\)', comparison_data)
            if single_classes_ratio_match:
                ratio_str = single_classes_ratio_match.group(1)
                if ratio_str == 'infx':
                    result['dual_analysis']['effectiveness_gap']['single_classes_ratio'] = float('inf')
                else:
                    result['dual_analysis']['effectiveness_gap']['single_classes_ratio'] = float(ratio_str.replace('x', ''))
            
            two_digit_ratio_match = re.search(r'Two-digit classes:.*?vs.*?\(([0-9.]+x|infx)\)', comparison_data)
            if two_digit_ratio_match:
                ratio_str = two_digit_ratio_match.group(1)
                if ratio_str == 'infx':
                    result['dual_analysis']['effectiveness_gap']['two_digit_ratio'] = float('inf')
                else:
                    result['dual_analysis']['effectiveness_gap']['two_digit_ratio'] = float(ratio_str.replace('x', ''))
            
            three_char_ratio_match = re.search(r'Three-char classes:.*?vs.*?\(([0-9.]+x|infx)\)', comparison_data)
            if three_char_ratio_match:
                ratio_str = three_char_ratio_match.group(1)
                if ratio_str == 'infx':
                    result['dual_analysis']['effectiveness_gap']['three_char_ratio'] = float('inf')
                else:
                    result['dual_analysis']['effectiveness_gap']['three_char_ratio'] = float(ratio_str.replace('x', ''))
            
            method_ratio_match = re.search(r'Single methods:.*?vs.*?\(([0-9.]+x|infx)\)', comparison_data)
            if method_ratio_match:
                ratio_str = method_ratio_match.group(1)
                if ratio_str == 'infx':
                    result['dual_analysis']['effectiveness_gap']['single_method_ratio'] = float('inf')
                else:
                    result['dual_analysis']['effectiveness_gap']['single_method_ratio'] = float(ratio_str.replace('x', ''))
        
        # Extract final assessment agreement
        if 'Agreement: ✅ CONSISTENT' in section:
            result['dual_analysis']['effectiveness_gap']['agreement'] = 'CONSISTENT'
        elif 'Agreement: ⚠️ DIFFERENT' in section:
            result['dual_analysis']['effectiveness_gap']['agreement'] = 'DIFFERENT'
        
        # Extract method results from the YARA-STRICT vs MANUAL ANALYSIS Comparison section
        comparison_section = re.search(r'📊 YARA-STRICT vs MANUAL ANALYSIS Comparison:(.*?)📊 Final Assessment:', section, re.DOTALL)
        if comparison_section:
            comparison_data = comparison_section.group(1)
            
            # Parse individual methods using exact patterns from console output
            methods = [
                ('Method 1 - Short strings', 'Method_1_Short_strings'),
                ('Method 2 - Single classes', 'Method_2_Single_classes'),
                ('Method 3 - Two-char classes', 'Method_3_Two_char_classes'),
                ('Method 3b - Three-char classes', 'Method_3b_Three_char_classes'),
                ('Method 4 - Single methods', 'Method_4_Single_methods'),
                ('Method 5 - Combined extreme', 'Method_5_Combined_extreme')
            ]
            
            for method_pattern, method_name in methods:
                # Find the method section
                method_section = re.search(rf'{re.escape(method_pattern)}:(.*?)(?=Method \d|\Z)', comparison_data, re.DOTALL)
                if method_section:
                    method_data = method_section.group(1)
                    
                    # Check YARA result
                    if '   YARA:   ✅ PASS' in method_data:
                        yara_methods_passed.append(method_name)
                    elif '   YARA:   ❌ FAIL' in method_data:
                        yara_methods_failed.append(method_name)
                    else:
                        yara_methods_failed.append(method_name)
                    
                    # Check Manual result
                    if '   MANUAL: ✅ PASS' in method_data:
                        manual_methods_passed.append(method_name)
                    elif '   MANUAL: ❌ FAIL' in method_data:
                        manual_methods_failed.append(method_name)
                    else:
                        manual_methods_failed.append(method_name)
                else:
                    # Method not found, default to failed
                    yara_methods_failed.append(method_name)
                    manual_methods_failed.append(method_name)
            
            # Update the results
            result['dual_analysis']['yara_strict']['methods_passed'] = yara_methods_passed
            result['dual_analysis']['yara_strict']['methods_failed'] = yara_methods_failed
            result['dual_analysis']['yara_strict']['methods_passed_count'] = len(yara_methods_passed)
            
            result['dual_analysis']['manual_inspection']['methods_passed'] = manual_methods_passed
            result['dual_analysis']['manual_inspection']['methods_failed'] = manual_methods_failed
            result['dual_analysis']['manual_inspection']['methods_passed_count'] = len(manual_methods_passed)
        
        # Extract final trigger decisions from the Final Assessment section
        final_assessment_section = re.search(r'📊 Final Assessment:(.*?)================================================================================', section, re.DOTALL)
        if final_assessment_section:
            final_data = final_assessment_section.group(1)
            
            # Extract YARA-STRICT should trigger
            if 'Rule should trigger: 🔴 YES' in final_data:
                result['dual_analysis']['yara_strict']['should_trigger'] = True
            elif 'Rule should trigger: 🟢 NO' in final_data:
                result['dual_analysis']['yara_strict']['should_trigger'] = False
            
            # Extract MANUAL INSPECTION should trigger
            if 'Rule would trigger: 🔴 YES' in final_data:
                result['dual_analysis']['manual_inspection']['should_trigger'] = True
            elif 'Rule would trigger: 🟢 NO' in final_data:
                result['dual_analysis']['manual_inspection']['should_trigger'] = False
        
        # Calculate methods gap
        yara_count = result['dual_analysis']['yara_strict']['methods_passed_count']
        manual_count = result['dual_analysis']['manual_inspection']['methods_passed_count']
        result['dual_analysis']['effectiveness_gap']['methods_gap'] = manual_count - yara_count
        
        # For backward compatibility, use YARA-strict results as primary
        result['total_classes'] = result['dual_analysis']['yara_strict']['total_classes']
        result['logical_classes'] = result['dual_analysis']['yara_strict']['logical_classes']
        result['should_trigger'] = result['dual_analysis']['yara_strict']['should_trigger']
        result['methods_passed'] = result['dual_analysis']['yara_strict']['methods_passed']
        result['methods_failed'] = result['dual_analysis']['yara_strict']['methods_failed']
        
        # Clean up temporary variables
        if '_main_zebra_symbol_classes' in result:
            del result['_main_zebra_symbol_classes']
        if '_main_non_discovered_sdk_classes' in result:
            del result['_main_non_discovered_sdk_classes']
        
        return result
        
    except Exception as e:
        return {
            'parse_error': f'Failed to parse individual DEX result: {e}',
            'raw_section_sample': section[:500] + ('...' if len(section) > 500 else '')
        }
    try:
        result = {
            'dex_name': 'unknown',
            'dex_size_bytes': 0,
            'total_classes': 0,
            'logical_classes': 0,
            'conditions_passed': 0,
            'total_conditions': 0,
            'completion_percentage': 0.0,
            'should_trigger': False,
            'methods_passed': [],
            'methods_failed': [],
            'method_details': {},
            'dual_analysis': {
                'yara_strict': {
                    'total_classes': 0,
                    'logical_classes': 0,
                    'short_strings': 0,
                    'single_classes': 0,
                    'two_digit_classes': 0,
                    'three_char_classes': 0,
                    'single_methods': 0,
                    'methods_passed': [],
                    'methods_failed': [],
                    'methods_passed_count': 0,
                    'should_trigger': False,
                    'method_details': {}
                },
                'manual_inspection': {
                    'total_classes': 0,
                    'logical_classes': 0,
                    'non_discovered_sdk_classes': 0,
                    'zebra_symbol_classes': 0,
                    'short_strings': 0,
                    'single_classes': 0,
                    'two_digit_classes': 0,
                    'three_char_classes': 0,
                    'single_methods': 0,
                    'methods_passed': [],
                    'methods_failed': [],
                    'methods_passed_count': 0,
                    'should_trigger': False,
                    'method_details': {}
                },
                'effectiveness_gap': {
                    'short_strings_ratio': 0.0,
                    'single_classes_ratio': 0.0,
                    'two_digit_ratio': 0.0,
                    'three_char_ratio': 0.0,
                    'single_method_ratio': 0.0,
                    'methods_gap': 0,
                    'agreement': 'UNKNOWN'
                }
            }
        }
        
        # Extract DEX name
        name_match = re.search(r'(\w+\.dex)', section)
        if name_match:
            result['dex_name'] = name_match.group(1)
        
        # Extract DEX size
        size_match = re.search(r'DEX file size:\s*([0-9,]+)\s*bytes', section)
        if size_match:
            result['dex_size_bytes'] = int(size_match.group(1).replace(',', ''))
        
        # Extract Zebra/Symbol classes from main analysis section (before YARA-STRICT)
        main_analysis_section = re.search(r'📊 Manual analysis - using zebra_sdk_discovery\.py logic:(.*?)📈 Raw Pattern Counts:', section, re.DOTALL)
        if main_analysis_section:
            main_data = main_analysis_section.group(1)
            
            # Extract Zebra/Symbol classes count from main section
            main_zebra_symbol_match = re.search(r'Zebra/Symbol classes:\s*([0-9,]+)', main_data)
            if main_zebra_symbol_match:
                zebra_symbol_count = int(main_zebra_symbol_match.group(1).replace(',', ''))
                # Store this for later use in manual inspection section
                result['_main_zebra_symbol_classes'] = zebra_symbol_count
            
            # Extract non-discovered SDK classes from main section
            main_non_discovered_match = re.search(r'Non-discovered SDK classes:\s*([0-9,]+)', main_data)
            if main_non_discovered_match:
                non_discovered_count = int(main_non_discovered_match.group(1).replace(',', ''))
                result['_main_non_discovered_sdk_classes'] = non_discovered_count
        
        # Extract YARA-STRICT Analysis data
        yara_section = re.search(r'📊 YARA-STRICT Analysis.*?───────────────────────────────────────────────(.*?)📋 MANUAL INSPECTION Analysis', section, re.DOTALL)
        if yara_section:
            yara_data = yara_section.group(1)
            
            # Extract YARA counts - IMPORTANT: Use DEX header classes as total, not YARA pattern count
            yara_pattern_count_match = re.search(r'Total classes \(L\.\.\.;\):\s*([0-9,]+)', yara_data)
            yara_dex_header_match = re.search(r'DEX header classes:\s*([0-9,]+)', yara_data)
            yara_logical_match = re.search(r'Logical classes:\s*([0-9,]+)', yara_data)
            
            # Use DEX header classes as the true total count, not the YARA pattern count
            if yara_dex_header_match:
                result['dual_analysis']['yara_strict']['total_classes'] = int(yara_dex_header_match.group(1).replace(',', ''))
            elif yara_pattern_count_match:
                # Fallback to pattern count if DEX header not available
                result['dual_analysis']['yara_strict']['total_classes'] = int(yara_pattern_count_match.group(1).replace(',', ''))
            
            if yara_logical_match:
                # Logical classes can be negative due to calculation errors in the source
                logical_classes = int(yara_logical_match.group(1).replace(',', ''))
                # Ensure logical classes don't exceed total classes (data integrity fix)
                total_classes = result['dual_analysis']['yara_strict']['total_classes']
                if logical_classes > total_classes and total_classes > 0:
                    # Log this anomaly but cap logical classes to total classes
                    result['dual_analysis']['yara_strict']['logical_classes'] = total_classes
                    result['dual_analysis']['yara_strict']['_logical_anomaly'] = {
                        'original_logical': logical_classes,
                        'capped_to_total': total_classes,
                        'anomaly_type': 'logical_exceeds_total'
                    }
                else:
                    result['dual_analysis']['yara_strict']['logical_classes'] = max(0, logical_classes)  # Ensure non-negative
            
            yara_short_strings_match = re.search(r'Short strings \(a-e\):\s*([0-9,]+)', yara_data)
            if yara_short_strings_match:
                result['dual_analysis']['yara_strict']['short_strings'] = int(yara_short_strings_match.group(1).replace(',', ''))
            
            yara_single_classes_match = re.search(r'Single class names:\s*([0-9,]+)', yara_data)
            if yara_single_classes_match:
                result['dual_analysis']['yara_strict']['single_classes'] = int(yara_single_classes_match.group(1).replace(',', ''))
            
            yara_two_char_match = re.search(r'Two-char classes:\s*([0-9,]+)', yara_data)
            if yara_two_char_match:
                result['dual_analysis']['yara_strict']['two_digit_classes'] = int(yara_two_char_match.group(1).replace(',', ''))
            
            yara_three_char_match = re.search(r'Three-char classes:\s*([0-9,]+)', yara_data)
            if yara_three_char_match:
                result['dual_analysis']['yara_strict']['three_char_classes'] = int(yara_three_char_match.group(1).replace(',', ''))
            
            yara_methods_match = re.search(r'Single methods:\s*([0-9,]+)', yara_data)
            if yara_methods_match:
                result['dual_analysis']['yara_strict']['single_methods'] = int(yara_methods_match.group(1).replace(',', ''))
            
            # Extract YARA methods passed - look in the comparison section instead
            yara_methods_passed = []
            yara_methods_failed = []
            
            # Extract YARA should trigger
            if 'Rule should trigger: 🔴 YES' in yara_data:
                result['dual_analysis']['yara_strict']['should_trigger'] = True
            elif 'Rule should trigger: 🟢 NO' in yara_data:
                result['dual_analysis']['yara_strict']['should_trigger'] = False
        
        # Extract MANUAL INSPECTION Analysis data
        manual_section = re.search(r'📋 MANUAL INSPECTION Analysis.*?───────────────────────────────────────────────(.*?)🔍 COMPARISON', section, re.DOTALL)
        if manual_section:
            manual_data = manual_section.group(1)
            
            # Extract manual counts
            manual_total_match = re.search(r'Total unique classes:\s*([0-9,]+)', manual_data)
            if manual_total_match:
                result['dual_analysis']['manual_inspection']['total_classes'] = int(manual_total_match.group(1).replace(',', ''))
            
            manual_logical_match = re.search(r'Logical classes analyzed:\s*([0-9,]+)', manual_data)
            if manual_logical_match:
                result['dual_analysis']['manual_inspection']['logical_classes'] = int(manual_logical_match.group(1).replace(',', ''))
            
            # Extract non-discovered SDK classes count
            manual_non_discovered_match = re.search(r'Non-discovered SDK classes:\s*([0-9,]+)', manual_data)
            if manual_non_discovered_match:
                result['dual_analysis']['manual_inspection']['non_discovered_sdk_classes'] = int(manual_non_discovered_match.group(1).replace(',', ''))
            elif '_main_non_discovered_sdk_classes' in result:
                # Use value from main analysis section if not found in manual section
                result['dual_analysis']['manual_inspection']['non_discovered_sdk_classes'] = result['_main_non_discovered_sdk_classes']
            
            # Extract Zebra/Symbol classes count
            manual_zebra_symbol_match = re.search(r'Zebra/Symbol classes:\s*([0-9,]+)', manual_data)
            if manual_zebra_symbol_match:
                result['dual_analysis']['manual_inspection']['zebra_symbol_classes'] = int(manual_zebra_symbol_match.group(1).replace(',', ''))
            elif '_main_zebra_symbol_classes' in result:
                # Use value from main analysis section if not found in manual section
                result['dual_analysis']['manual_inspection']['zebra_symbol_classes'] = result['_main_zebra_symbol_classes']
            
            manual_short_strings_match = re.search(r'Short strings \(a-e\):\s*([0-9,]+)', manual_data)
            if manual_short_strings_match:
                result['dual_analysis']['manual_inspection']['short_strings'] = int(manual_short_strings_match.group(1).replace(',', ''))
            
            manual_single_classes_match = re.search(r'Single-digit classes:\s*([0-9,]+)', manual_data)
            if manual_single_classes_match:
                result['dual_analysis']['manual_inspection']['single_classes'] = int(manual_single_classes_match.group(1).replace(',', ''))
            
            manual_two_char_match = re.search(r'Two-digit classes:\s*([0-9,]+)', manual_data)
            if manual_two_char_match:
                result['dual_analysis']['manual_inspection']['two_digit_classes'] = int(manual_two_char_match.group(1).replace(',', ''))
            
            manual_three_char_match = re.search(r'Three-digit classes:\s*([0-9,]+)', manual_data)
            if manual_three_char_match:
                result['dual_analysis']['manual_inspection']['three_char_classes'] = int(manual_three_char_match.group(1).replace(',', ''))
            
            manual_methods_match = re.search(r'Single-char methods:\s*([0-9,]+)', manual_data)
            if manual_methods_match:
                result['dual_analysis']['manual_inspection']['single_methods'] = int(manual_methods_match.group(1).replace(',', ''))
            
            # Extract manual methods passed (look for manual analysis trigger logic)
            manual_methods_passed = []
            manual_methods_failed = []
            
            # Check if manual analysis would pass each method based on the same criteria
            # Note: Manual analysis uses broader patterns, so we need to check the "Rule would trigger" section
            if 'Rule would trigger: 🔴 YES' in manual_data:
                result['dual_analysis']['manual_inspection']['should_trigger'] = True
                # If manual triggers, we assume it passed more methods than YARA
                # We'll extract the specific method details from the comparison section
            elif 'Rule would trigger: 🟢 NO' in manual_data:
                result['dual_analysis']['manual_inspection']['should_trigger'] = False
        
        # Extract effectiveness gap data
        comparison_section = re.search(r'🔍 COMPARISON.*?───────────────────────────────────────(.*?)🎯 Detailed Condition', section, re.DOTALL)
        if comparison_section:
            comparison_data = comparison_section.group(1)
            
            # Extract all pattern ratios
            short_strings_ratio_match = re.search(r'Short strings \(a-e\):.*?vs.*?\(([0-9.]+x|infx)\)', comparison_data)
            if short_strings_ratio_match:
                ratio_str = short_strings_ratio_match.group(1)
                if ratio_str == 'infx':
                    result['dual_analysis']['effectiveness_gap']['short_strings_ratio'] = float('inf')
                else:
                    result['dual_analysis']['effectiveness_gap']['short_strings_ratio'] = float(ratio_str.replace('x', ''))
            
            single_classes_ratio_match = re.search(r'Single classes:.*?vs.*?\(([0-9.]+x|infx)\)', comparison_data)
            if single_classes_ratio_match:
                ratio_str = single_classes_ratio_match.group(1)
                if ratio_str == 'infx':
                    result['dual_analysis']['effectiveness_gap']['single_classes_ratio'] = float('inf')
                else:
                    result['dual_analysis']['effectiveness_gap']['single_classes_ratio'] = float(ratio_str.replace('x', ''))
            
            two_digit_ratio_match = re.search(r'Two-digit classes:.*?vs.*?\(([0-9.]+x|infx)\)', comparison_data)
            if two_digit_ratio_match:
                ratio_str = two_digit_ratio_match.group(1)
                if ratio_str == 'infx':
                    result['dual_analysis']['effectiveness_gap']['two_digit_ratio'] = float('inf')
                else:
                    result['dual_analysis']['effectiveness_gap']['two_digit_ratio'] = float(ratio_str.replace('x', ''))
            
            three_char_ratio_match = re.search(r'Three-char classes:.*?vs.*?\(([0-9.]+x|infx)\)', comparison_data)
            if three_char_ratio_match:
                ratio_str = three_char_ratio_match.group(1)
                if ratio_str == 'infx':
                    result['dual_analysis']['effectiveness_gap']['three_char_ratio'] = float('inf')
                else:
                    result['dual_analysis']['effectiveness_gap']['three_char_ratio'] = float(ratio_str.replace('x', ''))
            
            method_ratio_match = re.search(r'Single methods:.*?vs.*?\(([0-9.]+x|infx)\)', comparison_data)
            if method_ratio_match:
                ratio_str = method_ratio_match.group(1)
                if ratio_str == 'infx':
                    result['dual_analysis']['effectiveness_gap']['single_method_ratio'] = float('inf')
                else:
                    result['dual_analysis']['effectiveness_gap']['single_method_ratio'] = float(ratio_str.replace('x', ''))
        
        # Extract final assessment agreement
        if 'Agreement: ✅ CONSISTENT' in section:
            result['dual_analysis']['effectiveness_gap']['agreement'] = 'CONSISTENT'
        elif 'Agreement: ⚠️ DIFFERENT' in section:
            result['dual_analysis']['effectiveness_gap']['agreement'] = 'DIFFERENT'
        
        # Extract method results from the YARA-STRICT vs MANUAL ANALYSIS Comparison section
        comparison_section = re.search(r'📊 YARA-STRICT vs MANUAL ANALYSIS Comparison:(.*?)📊 Final Assessment:', section, re.DOTALL)
        if comparison_section:
            comparison_data = comparison_section.group(1)
            
            # Parse individual methods using exact patterns from console output
            methods = [
                ('Method 1 - Short strings', 'Method_1_Short_strings'),
                ('Method 2 - Single classes', 'Method_2_Single_classes'),
                ('Method 3 - Two-char classes', 'Method_3_Two_char_classes'),
                ('Method 3b - Three-char classes', 'Method_3b_Three_char_classes'),
                ('Method 4 - Single methods', 'Method_4_Single_methods'),
                ('Method 5 - Combined extreme', 'Method_5_Combined_extreme')
            ]
            
            for method_pattern, method_name in methods:
                # Find the method section
                method_section = re.search(rf'{re.escape(method_pattern)}:(.*?)(?=Method \d|\Z)', comparison_data, re.DOTALL)
                if method_section:
                    method_data = method_section.group(1)
                    
                    # Check YARA result
                    if '   YARA:   ✅ PASS' in method_data:
                        yara_methods_passed.append(method_name)
                    elif '   YARA:   ❌ FAIL' in method_data:
                        yara_methods_failed.append(method_name)
                    else:
                        yara_methods_failed.append(method_name)
                    
                    # Check Manual result
                    if '   MANUAL: ✅ PASS' in method_data:
                        manual_methods_passed.append(method_name)
                    elif '   MANUAL: ❌ FAIL' in method_data:
                        manual_methods_failed.append(method_name)
                    else:
                        manual_methods_failed.append(method_name)
                else:
                    # Method not found, default to failed
                    yara_methods_failed.append(method_name)
                    manual_methods_failed.append(method_name)
            
            # Update the results
            result['dual_analysis']['yara_strict']['methods_passed'] = yara_methods_passed
            result['dual_analysis']['yara_strict']['methods_failed'] = yara_methods_failed
            result['dual_analysis']['yara_strict']['methods_passed_count'] = len(yara_methods_passed)
            
            result['dual_analysis']['manual_inspection']['methods_passed'] = manual_methods_passed
            result['dual_analysis']['manual_inspection']['methods_failed'] = manual_methods_failed
            result['dual_analysis']['manual_inspection']['methods_passed_count'] = len(manual_methods_passed)
        
        # Extract final trigger decisions from the Final Assessment section
        final_assessment_section = re.search(r'📊 Final Assessment:(.*?)================================================================================', section, re.DOTALL)
        if final_assessment_section:
            final_data = final_assessment_section.group(1)
            
            # Extract YARA-STRICT should trigger
            if 'Rule should trigger: 🔴 YES' in final_data:
                result['dual_analysis']['yara_strict']['should_trigger'] = True
            elif 'Rule should trigger: 🟢 NO' in final_data:
                result['dual_analysis']['yara_strict']['should_trigger'] = False
            
            # Extract MANUAL INSPECTION should trigger
            if 'Rule would trigger: 🔴 YES' in final_data:
                result['dual_analysis']['manual_inspection']['should_trigger'] = True
            elif 'Rule would trigger: 🟢 NO' in final_data:
                result['dual_analysis']['manual_inspection']['should_trigger'] = False
        
        # Calculate methods gap
        yara_count = result['dual_analysis']['yara_strict']['methods_passed_count']
        manual_count = result['dual_analysis']['manual_inspection']['methods_passed_count']
        result['dual_analysis']['effectiveness_gap']['methods_gap'] = manual_count - yara_count
        
        # For backward compatibility, use YARA-strict results as primary
        result['total_classes'] = result['dual_analysis']['yara_strict']['total_classes']
        result['logical_classes'] = result['dual_analysis']['yara_strict']['logical_classes']
        result['should_trigger'] = result['dual_analysis']['yara_strict']['should_trigger']
        result['methods_passed'] = result['dual_analysis']['yara_strict']['methods_passed']
        result['methods_failed'] = result['dual_analysis']['yara_strict']['methods_failed']
        
        # Clean up temporary variables
        if '_main_zebra_symbol_classes' in result:
            del result['_main_zebra_symbol_classes']
        if '_main_non_discovered_sdk_classes' in result:
            del result['_main_non_discovered_sdk_classes']
        
        return result
        
    except Exception as e:
        return {
            'parse_error': f'Failed to parse individual DEX result: {e}',
            'raw_section_sample': section[:500] + ('...' if len(section) > 500 else '')
        }


def calculate_rule_parameter_margin_status(rule_config, actual_values, analysis_type="manual_investigation"):
    """
    Calculate margin status based on enabled rule parameters from the configuration.
    
    Args:
        rule_config: Dictionary containing rule configuration with thresholds
        actual_values: Dictionary containing actual measured values
        analysis_type: "manual_investigation" or "yara_strict"
    
    Returns:
        Dictionary with detailed margin status including enabled parameters only
    """
    
    # The 7 core parameters to check
    parameter_mapping = {
        'short_char': 'short_strings',  # Maps to short_strings in actual values
        'short_method': 'single_methods',  # Maps to single_methods in actual values
        'combined_short_rule': None,  # Calculated field
        'single_char_classes': 'single_classes',  # Maps to single_classes
        'two_char_classes': 'two_digit_classes',  # Maps to two_digit_classes  
        'three_char_classes': 'three_char_classes',  # Direct mapping
        'combined_class_rule': None  # Calculated field (percentage-based)
    }
    
    # Get enabled parameters (non-zero values)
    enabled_parameters = []
    parameter_evaluations = []
    
    if not rule_config or 'thresholds' not in rule_config:
        return {
            'status': 'UNKNOWN',
            'margin': 0,
            'parameters_passed': 0,
            'total_enabled_parameters': 0,
            'enabled_parameters': [],
            'parameter_evaluations': [],
            'optimal_threshold': 0,
            'minimal_threshold': 0,
            'margin_description': 'No rule configuration available'
        }
    
    thresholds = rule_config['thresholds']
    
    # Check each parameter to see if it's enabled (non-zero)
    for param_name, actual_field in parameter_mapping.items():
        threshold_value = thresholds.get(param_name, 0)
        
        # Skip disabled parameters (value is 0)
        if threshold_value == 0 or threshold_value == "0":
            continue
            
        enabled_parameters.append(param_name)
        
        # Get actual value for comparison
        actual_value = 0
        if actual_field and actual_field in actual_values:
            actual_value = actual_values[actual_field]
        elif param_name == 'combined_short_rule':
            # Calculate combined short rule (sum of short strings and methods)
            actual_value = actual_values.get('short_strings', 0) + actual_values.get('single_methods', 0)
        elif param_name == 'combined_class_rule':
            # Calculate combined class rule (percentage of logical classes)
            logical_classes = actual_values.get('logical_classes', 0)
            short_classes = (actual_values.get('single_classes', 0) + 
                           actual_values.get('two_digit_classes', 0) + 
                           actual_values.get('three_char_classes', 0))
            
            # Fix for zero logical classes: treat as 1 to avoid division by zero
            # This allows percentage calculation to work normally for obfuscated/packed APKs
            effective_logical_classes = max(logical_classes, 1)
            
            actual_percentage = (short_classes / effective_logical_classes)
            # Parse threshold (e.g., "0.3x" -> 0.3)
            if isinstance(threshold_value, str) and threshold_value.endswith('x'):
                threshold_percentage = float(threshold_value[:-1])
                passed = actual_percentage >= threshold_percentage
                
                # Create descriptive message
                if logical_classes == 0:
                    description = f'Zero logical classes (treated as 1): {short_classes} short classes = {actual_percentage:.1f}x vs {threshold_percentage:.1f}x threshold'
                else:
                    description = f'Combined class obfuscation: {actual_percentage:.1%} vs {threshold_percentage:.1%} threshold'
                
                parameter_evaluations.append({
                    'parameter': param_name,
                    'threshold': threshold_value,
                    'actual_value': f"{actual_percentage:.3f}x",
                    'passed': passed,
                    'description': description
                })
                continue
        
        # Regular numeric comparison
        if isinstance(threshold_value, (int, float)) or str(threshold_value).isdigit():
            threshold_num = float(threshold_value)
            passed = actual_value >= threshold_num
            parameter_evaluations.append({
                'parameter': param_name,
                'threshold': threshold_value,
                'actual_value': actual_value,
                'passed': passed,
                'description': f'{param_name}: {actual_value} vs {threshold_value} threshold'
            })
    
    # Count how many parameters passed
    parameters_passed = sum(1 for eval_result in parameter_evaluations if eval_result['passed'])
    total_enabled_parameters = len(enabled_parameters)
    
    # Define thresholds based on enabled parameters
    if total_enabled_parameters == 0:
        return {
            'status': 'NO_ENABLED_PARAMETERS',
            'margin': 0,
            'parameters_passed': 0,
            'total_enabled_parameters': 0,
            'enabled_parameters': [],
            'parameter_evaluations': [],
            'optimal_threshold': 0,
            'minimal_threshold': 0,
            'margin_description': 'No parameters enabled in rule configuration'
        }
    
    # Calculate percentage-based thresholds
    # OPTIMAL: 60% of enabled parameters should pass
    # MINIMAL: 30% of enabled parameters should pass (minimum 1)
    optimal_threshold = max(1, int(total_enabled_parameters * 0.6))
    minimal_threshold = max(1, int(total_enabled_parameters * 0.3))
    
    # Determine status and margins
    if parameters_passed >= optimal_threshold:
        margin_from_optimal = parameters_passed - optimal_threshold
        percentage_above = (parameters_passed / total_enabled_parameters) * 100
        status = 'OPTIMAL'
        margin = margin_from_optimal
        margin_description = f'OPTIMAL: {parameters_passed}/{total_enabled_parameters} parameters passed ({percentage_above:.1f}%), {margin_from_optimal} above optimal threshold'
    elif parameters_passed >= minimal_threshold:
        margin_from_optimal = optimal_threshold - parameters_passed
        margin_from_minimal = parameters_passed - minimal_threshold
        percentage_achieved = (parameters_passed / total_enabled_parameters) * 100
        status = 'MINIMAL'
        margin = margin_from_optimal  # How far from optimal
        margin_description = f'MINIMAL: {parameters_passed}/{total_enabled_parameters} parameters passed ({percentage_achieved:.1f}%), {margin_from_optimal} short of optimal, {margin_from_minimal} above minimal'
    else:
        margin_from_minimal = minimal_threshold - parameters_passed
        margin_from_optimal = optimal_threshold - parameters_passed
        percentage_achieved = (parameters_passed / total_enabled_parameters) * 100
        status = 'FAILED'
        margin = margin_from_minimal  # How far from minimal
        margin_description = f'FAILED: {parameters_passed}/{total_enabled_parameters} parameters passed ({percentage_achieved:.1f}%), {margin_from_minimal} short of minimal, {margin_from_optimal} short of optimal'
    
    return {
        'status': status,
        'margin': margin,
        'parameters_passed': parameters_passed,
        'total_enabled_parameters': total_enabled_parameters,
        'enabled_parameters': enabled_parameters,
        'parameter_evaluations': parameter_evaluations,
        'optimal_threshold': optimal_threshold,
        'minimal_threshold': minimal_threshold,
        'margin_description': margin_description,
        'percentage_achieved': (parameters_passed / total_enabled_parameters) * 100 if total_enabled_parameters > 0 else 0
    }

def create_comprehensive_final_summary(result_data):
    """
    Create a comprehensive final summary that includes:
    1. Manual Investigation Summary
    2. Strict YARA Summary  
    3. APKiD Analysis Summary
    4. R8 Marker Analysis Summary
    
    Enhanced with rule-based parameter margin calculation.
    """
    import json
    import os
    
    summary = {
        'manual_investigation_summary': {
            'rules_passed': [],
            'margin_status': {
                'status': 'UNKNOWN',
                'margin': 0,
                'parameters_passed': 0,
                'total_enabled_parameters': 0,
                'enabled_parameters': [],
                'parameter_evaluations': [],
                'optimal_threshold': 0,
                'minimal_threshold': 0,
                'margin_description': 'Analysis not available'
            },
            'obfuscation_percentages': {
                'class_name_obfuscation': 0.0,
                'method_name_obfuscation': 0.0
            },
            'analysis_available': False
        },
        'strict_yara_summary': {
            'rules_passed': [],
            'margin_status': {
                'status': 'UNKNOWN',
                'margin': 0,
                'parameters_passed': 0,
                'total_enabled_parameters': 0,
                'enabled_parameters': [],
                'parameter_evaluations': [],
                'optimal_threshold': 0,
                'minimal_threshold': 0,
                'margin_description': 'Analysis not available'
            },
            'analysis_available': False
        },
        'apkid_analysis_summary': {
            'manipulator_detected': False,
            'obfuscator_assessment': 'UNKNOWN',
            'libs_obfuscated_status': 'UNKNOWN',
            'compiler': 'UNKNOWN',
            'arxan_indicators': [],
            'analysis_available': False
        },
        'r8_marker_analysis': {
            'marker_found': False,
            'marker_status': 'UNKNOWN',
            'compilation_details': {},
            'analysis_available': False
        }
    }
    
    # Load rule configuration for parameter-based margin calculation
    rule_config = None
    config_path = os.path.join(os.path.dirname(__file__), 'obfuscation_rules_config.json')
    try:
        with open(config_path, 'r') as f:
            rule_config = json.load(f)
    except Exception as e:
        print(f"Warning: Could not load rule configuration: {e}")
    
    # Check if comprehensive analysis is available
    comprehensive_result = result_data.get('comprehensive_massive_obf_result')
    if not comprehensive_result or not comprehensive_result.get('success'):
        return summary

    parsed_analysis = comprehensive_result.get('parsed_analysis', {})
    final_dual_analysis = parsed_analysis.get('final_dual_analysis', {})
    detailed_results = parsed_analysis.get('detailed_results', [])
    
    # Determine DEX count for rule selection
    dex_count = final_dual_analysis.get('total_dex_files', 1)
    
    # Determine rule category based on logical classes and DEX count (matching comprehensive analysis logic)
    manual_logical_classes = final_dual_analysis.get('aggregated_analysis', {}).get('manual_inspection', {}).get('logical_classes', 0)
    if manual_logical_classes < 50:
        rule_category = 'small_dex'
    elif dex_count == 1:
        rule_category = 'single_dex'
    else:
        rule_category = 'multi_dex'    # 1. Manual Investigation Summary
    if final_dual_analysis and final_dual_analysis.get('aggregated_analysis', {}).get('manual_inspection'):
        manual_data = final_dual_analysis['aggregated_analysis']['manual_inspection']
        summary['manual_investigation_summary']['analysis_available'] = True
        
        # Extract actual rule names that passed from raw stdout
        rules_passed = []
        raw_stdout = comprehensive_result.get('stdout', '')
        
        # NEW LOGIC: Check actual parameter evaluation results instead of just rule selection
        # Look for rules that actually PASSED their parameter evaluation, not just were selected
        
        # Check if manual investigation optimal/minimal rules actually passed their parameter evaluation
        manual_optimal_rule_passed = False
        manual_minimal_rule_passed = False
        
        # Get the actual parameter evaluation from our margin calculation
        if rule_config and rule_config.get('rules', {}).get(rule_category, {}).get('manual_investigation'):
            rule_optimal = rule_config['rules'][rule_category]['manual_investigation'].get('optimal')
            rule_minimal = rule_config['rules'][rule_category]['manual_investigation'].get('minimal')
            
            # Check optimal rule
            if rule_optimal:
                optimal_result = calculate_rule_parameter_margin_status(rule_optimal, manual_data, "manual_investigation")
                if optimal_result['parameters_passed'] >= optimal_result['optimal_threshold']:
                    manual_optimal_rule_passed = True
                    # Extract the specific rule name from stdout
                    optimal_rule_match = re.search(r'Selected optimal rule: (Manual Investigation[^\n]+)', raw_stdout)
                    if optimal_rule_match:
                        rules_passed.append(optimal_rule_match.group(1).strip())
                    else:
                        rules_passed.append("Manual Investigation Optimal Rule")
            
            # Check minimal rule (only if optimal didn't pass)
            if not manual_optimal_rule_passed and rule_minimal:
                minimal_result = calculate_rule_parameter_margin_status(rule_minimal, manual_data, "manual_investigation")
                if minimal_result['parameters_passed'] >= minimal_result['minimal_threshold']:
                    manual_minimal_rule_passed = True
                    # Extract the specific rule name from stdout
                    minimal_rule_match = re.search(r'Selected minimal rule: (Manual Investigation[^\n]+)', raw_stdout)
                    if minimal_rule_match:
                        rules_passed.append(minimal_rule_match.group(1).strip())
                    else:
                        rules_passed.append("Manual Investigation Minimal Rule")
        
        # If no rules passed parameter evaluation, fall back to individual methods for backward compatibility
        if not rules_passed:
            methods_passed = manual_data.get('methods_passed', [])
            if methods_passed:
                rules_passed = methods_passed  # Keep old behavior as fallback
        
        summary['manual_investigation_summary']['rules_passed'] = rules_passed
        
        # NEW: Calculate margin status based on enabled rule parameters
        manual_margin_status = {'status': 'UNKNOWN', 'margin': 0, 'parameters_passed': 0, 
                               'total_enabled_parameters': 0, 'margin_description': 'Rule config not available'}
        
        # Determine rule category based on logical classes for manual investigation
        manual_logical_classes = manual_data.get('logical_classes', 0)
        if manual_logical_classes < 50:
            manual_rule_category = 'small_dex'
        elif dex_count == 1:
            manual_rule_category = 'single_dex'
        else:
            manual_rule_category = 'multi_dex'
        
        # Store the category in the summary
        summary['manual_investigation_summary']['selected_rule_category'] = manual_rule_category
        
        # Get appropriate rule configuration for manual investigation
        if rule_config and rule_config.get('rules', {}).get(manual_rule_category, {}).get('manual_investigation'):
            # Try optimal rule first, fall back to minimal
            rule_optimal = rule_config['rules'][manual_rule_category]['manual_investigation'].get('optimal')
            rule_minimal = rule_config['rules'][manual_rule_category]['manual_investigation'].get('minimal')
            
            # Choose rule based on logical classes and which rule triggered
            logical_classes = manual_data.get('logical_classes', 0)
            selected_rule = None
            
            # If optimal rule triggered, use optimal config
            if any("optimal" in rule.lower() for rule in rules_passed):
                selected_rule = rule_optimal
            # If minimal rule triggered, use minimal config
            elif any("minimal" in rule.lower() for rule in rules_passed):
                selected_rule = rule_minimal
            # If no specific rule triggered, choose based on logical classes
            elif rule_optimal:
                applicable_when = rule_optimal.get('applicable_when', {})
                min_classes = applicable_when.get('logical_classes_min')
                max_classes = applicable_when.get('logical_classes_max')
                
                # Check if rule applies based on logical class count
                if min_classes is not None and logical_classes >= min_classes:
                    selected_rule = rule_optimal
                elif max_classes is not None and logical_classes <= max_classes:
                    selected_rule = rule_optimal
            elif rule_minimal:
                applicable_when = rule_minimal.get('applicable_when', {})
                min_classes = applicable_when.get('logical_classes_min')
                max_classes = applicable_when.get('logical_classes_max')
                
                # Check if rule applies based on logical class count
                if min_classes is not None and logical_classes >= min_classes:
                    selected_rule = rule_minimal
                elif max_classes is not None and logical_classes <= max_classes:
                    selected_rule = rule_minimal
            
            if selected_rule:
                manual_margin_status = calculate_rule_parameter_margin_status(
                    selected_rule, manual_data, "manual_investigation"
                )
        
        summary['manual_investigation_summary']['margin_status'] = manual_margin_status
        
        # EXCEPTION RULE: Very large app with high logical classes
        # Apply to single_dex and multi_dex manual investigation when no rules passed
        if ((manual_rule_category == 'single_dex' or manual_rule_category == 'multi_dex') and 
            manual_margin_status['status'] == 'FAILED' and 
            manual_margin_status['parameters_passed'] == 0):
            
            # Get zebra classes and logical classes for exception rule
            zebra_symbol_classes = manual_data.get('zebra_symbol_classes', 0)
            logical_classes = manual_data.get('logical_classes', 0)
            
            # Get marker type from R8 analysis
            marker_type = 'Unknown'
            if summary.get('r8_marker_analysis', {}).get('compilation_details', {}).get('marker_type'):
                marker_type = summary['r8_marker_analysis']['compilation_details']['marker_type']
            
            # Calculate combined class rule percentage
            single_classes = manual_data.get('single_classes', 0)
            two_digit_classes = manual_data.get('two_digit_classes', 0) 
            three_char_classes = manual_data.get('three_char_classes', 0)
            total_short_classes = single_classes + two_digit_classes + three_char_classes
            
            # Calculate percentage with zero logical classes fix
            effective_logical_classes = max(logical_classes, 1)
            combined_class_percentage = (total_short_classes / effective_logical_classes) * 100
            
            # Exception rule conditions:
            # 1. Logical classes > 1000 (instead of zebra classes)
            # 2. Marker is not D8 or marker is not detected (Unknown/custom obfuscator)
            # 3. Combined class rule is at least 10% or more
            if (logical_classes > 1000 and 
                marker_type != 'D8' and 
                combined_class_percentage >= 10.0):
                
                # Override the failed status with exception rule pass
                manual_margin_status['status'] = 'EXCEPTION_PASS'
                manual_margin_status['parameters_passed'] = 1
                manual_margin_status['margin_description'] = f'EXCEPTION RULE PASSED: Very large app with high logical classes ({logical_classes} logical classes, {zebra_symbol_classes} zebra classes, {combined_class_percentage:.1f}% obfuscation, {marker_type} marker)'
                manual_margin_status['exception_rule_applied'] = True
                manual_margin_status['exception_details'] = {
                    'logical_classes': logical_classes,
                    'zebra_classes': zebra_symbol_classes,
                    'marker_type': marker_type,
                    'combined_class_percentage': combined_class_percentage,
                    'reason': 'very large app with high logical classes'
                }
                
                # Update the summary with the exception pass
                summary['manual_investigation_summary']['margin_status'] = manual_margin_status
        
        # Calculate obfuscation percentages
        total_classes = manual_data.get('total_classes', 0)
        logical_classes = manual_data.get('logical_classes', 0) 
        zebra_symbol_classes = manual_data.get('zebra_symbol_classes', 0)
        short_methods = manual_data.get('single_methods', 0)
        
        # Sum of all short class patterns
        single_classes = manual_data.get('single_classes', 0)
        two_digit_classes = manual_data.get('two_digit_classes', 0) 
        three_char_classes = manual_data.get('three_char_classes', 0)
        total_short_classes = single_classes + two_digit_classes + three_char_classes
        
        # Class name obfuscation: zebra/symbol classes / total short obfuscated classes
        if total_short_classes > 0:
            summary['manual_investigation_summary']['obfuscation_percentages']['class_name_obfuscation'] = (zebra_symbol_classes / total_short_classes) * 100
        
        # Method name obfuscation: short methods / logical classes
        if logical_classes > 0:
            summary['manual_investigation_summary']['obfuscation_percentages']['method_name_obfuscation'] = (short_methods / logical_classes) * 100
    
    # 2. Strict YARA Summary
    if final_dual_analysis and final_dual_analysis.get('aggregated_analysis', {}).get('yara_strict'):
        yara_data = final_dual_analysis['aggregated_analysis']['yara_strict']
        summary['strict_yara_summary']['analysis_available'] = True
        
        # Extract actual rule names that passed from raw stdout
        rules_passed = []
        raw_stdout = comprehensive_result.get('stdout', '')
        
        # NEW LOGIC: Check actual parameter evaluation results instead of just rule selection
        # Look for rules that actually PASSED their parameter evaluation, not just were selected
        
        # Check if YARA strict optimal rule actually passed its parameter evaluation
        yara_optimal_rule_passed = False
        yara_minimal_rule_passed = False
        
        # Get the actual parameter evaluation from our margin calculation
        if rule_config and rule_config.get('rules', {}).get(rule_category, {}).get('yara_strict'):
            rule_optimal = rule_config['rules'][rule_category]['yara_strict'].get('optimal')
            rule_minimal = rule_config['rules'][rule_category]['yara_strict'].get('minimal')
            
            # Check optimal rule
            if rule_optimal:
                optimal_result = calculate_rule_parameter_margin_status(rule_optimal, yara_data, "yara_strict")
                if optimal_result['parameters_passed'] >= optimal_result['optimal_threshold']:
                    yara_optimal_rule_passed = True
                    # Extract the specific rule name from stdout
                    optimal_rule_match = re.search(r'Selected optimal rule: (YARA Strict[^\n]+)', raw_stdout)
                    if optimal_rule_match:
                        rules_passed.append(optimal_rule_match.group(1).strip())
                    else:
                        rules_passed.append("YARA Strict Optimal Rule")
            
            # Check minimal rule (only if optimal didn't pass)
            if not yara_optimal_rule_passed and rule_minimal:
                minimal_result = calculate_rule_parameter_margin_status(rule_minimal, yara_data, "yara_strict")
                if minimal_result['parameters_passed'] >= minimal_result['minimal_threshold']:
                    yara_minimal_rule_passed = True
                    # Extract the specific rule name from stdout
                    minimal_rule_match = re.search(r'Selected minimal rule: (YARA Strict[^\n]+)', raw_stdout)
                    if minimal_rule_match:
                        rules_passed.append(minimal_rule_match.group(1).strip())
                    else:
                        rules_passed.append("YARA Strict Minimal Rule")
        
        # If no rules passed parameter evaluation, fall back to individual methods for backward compatibility
        if not rules_passed:
            methods_passed = yara_data.get('methods_passed', [])
            if methods_passed:
                rules_passed = methods_passed  # Keep old behavior as fallback
        
        summary['strict_yara_summary']['rules_passed'] = rules_passed
        
        # NEW: Calculate margin status based on enabled rule parameters
        yara_margin_status = {'status': 'UNKNOWN', 'margin': 0, 'parameters_passed': 0, 
                             'total_enabled_parameters': 0, 'margin_description': 'Rule config not available'}
        
        # Determine rule category based on logical classes for YARA strict
        yara_logical_classes = yara_data.get('logical_classes', 0)
        if yara_logical_classes < 50:
            yara_rule_category = 'small_dex'
        elif dex_count == 1:
            yara_rule_category = 'single_dex'
        else:
            yara_rule_category = 'multi_dex'
        
        # Get appropriate rule configuration for YARA strict
        if rule_config and rule_config.get('rules', {}).get(yara_rule_category, {}).get('yara_strict'):
            # Try optimal rule first, fall back to minimal
            rule_optimal = rule_config['rules'][yara_rule_category]['yara_strict'].get('optimal')
            rule_minimal = rule_config['rules'][yara_rule_category]['yara_strict'].get('minimal')
            
            # Choose rule based on logical classes and which rule triggered
            logical_classes = yara_data.get('logical_classes', 0)
            selected_rule = None
            
            # If optimal rule triggered, use optimal config
            if any("optimal" in rule.lower() for rule in rules_passed):
                selected_rule = rule_optimal
            # If minimal rule triggered, use minimal config
            elif any("minimal" in rule.lower() for rule in rules_passed):
                selected_rule = rule_minimal
            # If no specific rule triggered, choose based on logical classes
            elif rule_optimal:
                applicable_when = rule_optimal.get('applicable_when', {})
                min_classes = applicable_when.get('logical_classes_min')
                max_classes = applicable_when.get('logical_classes_max')
                
                # Check if rule applies based on logical class count
                if min_classes is not None and logical_classes >= min_classes:
                    selected_rule = rule_optimal
                elif max_classes is not None and logical_classes <= max_classes:
                    selected_rule = rule_optimal
            elif rule_minimal:
                applicable_when = rule_minimal.get('applicable_when', {})
                min_classes = applicable_when.get('logical_classes_min')
                max_classes = applicable_when.get('logical_classes_max')
                
                # Check if rule applies based on logical class count
                if min_classes is not None and logical_classes >= min_classes:
                    selected_rule = rule_minimal
                elif max_classes is not None and logical_classes <= max_classes:
                    selected_rule = rule_minimal
            
            if selected_rule:
                yara_margin_status = calculate_rule_parameter_margin_status(
                    selected_rule, yara_data, "yara_strict"
                )
        
        summary['strict_yara_summary']['margin_status'] = yara_margin_status
    
    # 3. APKiD Analysis Summary
    apkid_result = result_data.get('apkid_result')
    if apkid_result and apkid_result.get('success') and apkid_result.get('parsed_output'):
        summary['apkid_analysis_summary']['analysis_available'] = True
        apkid_data = apkid_result['parsed_output']
        
        # Check for manipulator detection
        manipulator_found = False
        arxan_indicators = []
        
        # Check all files for manipulator and Arxan indicators
        for file_data in apkid_data.get('files', []):
            matches = file_data.get('matches', {})
            filename = file_data.get('filename', 'unknown')
            
            # Check for manipulator key in matches
            if 'manipulator' in matches:
                manipulator_found = True
            
            # Check for Arxan in all detection categories
            for category, detections in matches.items():
                if isinstance(detections, list):
                    for detection in detections:
                        if 'arxan' in detection.lower():
                            arxan_indicators.append({
                                'file': filename,
                                'detection': detection
                            })
        
        summary['apkid_analysis_summary']['manipulator_detected'] = manipulator_found
        summary['apkid_analysis_summary']['arxan_indicators'] = arxan_indicators
        
        # NEW OBFUSCATOR ASSESSMENT LOGIC
        # Get R8 marker information
        r8_result = result_data.get('r8_extract_marker_result')
        r8_marker_found = False
        marker_type = 'Unknown'
        
        if r8_result and r8_result.get('success') and r8_result.get('parsed_marker'):
            marker_data = r8_result['parsed_marker']
            r8_marker_found = marker_data.get('marker_type') is not None and marker_data.get('marker_type') != ''
            if r8_marker_found:
                marker_type = marker_data.get('marker_type', 'Unknown')
        
        # Check if manual investigation rules passed
        manual_passed = summary['manual_investigation_summary']['margin_status']['status'] in ['OPTIMAL', 'MINIMAL']
        
        # Implement new obfuscator assessment rules
        if not r8_marker_found:  # marker_found == false
            # Rule 1: Search APKiD results for *.dex files and check for Arxan detection
            arxan_in_dex_files = False
            
            # Check all files in APKiD results for .dex files with Arxan detection
            for file_data in apkid_data.get('files', []):
                filename = file_data.get('filename', '')
                if filename.endswith('.dex'):
                    matches = file_data.get('matches', {})
                    # Check all detection categories for Arxan
                    for category, detections in matches.items():
                        if isinstance(detections, list):
                            for detection in detections:
                                if 'arxan' in detection.lower():
                                    arxan_in_dex_files = True
                                    break
                        if arxan_in_dex_files:
                            break
                    if arxan_in_dex_files:
                        break
            
            if arxan_in_dex_files:
                # If Arxan detected in any .dex file section
                summary['apkid_analysis_summary']['obfuscator_assessment'] = 'Arxan (Confirmed)'
            else:
                # If no Arxan detected in .dex files, check manual investigation
                if manual_passed:
                    # If manual investigation shows rules passed
                    summary['apkid_analysis_summary']['obfuscator_assessment'] = 'Arxan or DexGuard (Possibly)'
                else:
                    # If manual investigation doesn't show rules passed
                    summary['apkid_analysis_summary']['obfuscator_assessment'] = 'Unknown'
        
        else:  # marker_found == true
            # Rule 2: If marker is detected, use marker type from r8_marker_analysis
            summary['apkid_analysis_summary']['obfuscator_assessment'] = f'{marker_type} (Standard)'
        
        # Check for library obfuscation
        so_files_with_obfuscation = []
        for file_data in apkid_data.get('files', []):
            filename = file_data.get('filename', '')
            if filename.endswith('.so'):
                matches = file_data.get('matches', {})
                # Check if obfuscator category exists and has any detections
                obfuscator_matches = matches.get('obfuscator', [])
                if obfuscator_matches:  # If any obfuscator detections found
                    so_files_with_obfuscation.append(filename)
        
        if so_files_with_obfuscation:
            summary['apkid_analysis_summary']['libs_obfuscated_status'] = 'Libs obfuscated'
        else:
            summary['apkid_analysis_summary']['libs_obfuscated_status'] = 'No library obfuscation detected'
        
        # SIMPLE COMPILER DETECTION LOGIC
        # Check R8 marker status to determine compiler value
        r8_result = result_data.get('r8_extract_marker_result')
        r8_marker_found = False
        
        if r8_result and r8_result.get('success') and r8_result.get('parsed_marker'):
            marker_data = r8_result['parsed_marker']
            r8_marker_found = marker_data.get('marker_type') is not None and marker_data.get('marker_type') != ''
        
        if not r8_marker_found:  # marker_found == false
            # Take compiler information from APKiD result
            compiler_found = 'UNKNOWN'
            
            # Search all files for compiler detection in APKiD results
            for file_data in apkid_data.get('files', []):
                matches = file_data.get('matches', {})
                
                # Check for compiler key in matches
                if 'compiler' in matches:
                    compiler_detections = matches['compiler']
                    if isinstance(compiler_detections, list) and compiler_detections:
                        # Take the first compiler found
                        compiler_found = compiler_detections[0]
                        break
            
            summary['apkid_analysis_summary']['compiler'] = compiler_found
            
        else:  # marker_found == true
            # Use marker_type from r8_extract_marker_result
            marker_type = marker_data.get('marker_type', 'UNKNOWN')
            summary['apkid_analysis_summary']['compiler'] = marker_type
    
    # 4. R8 Marker Analysis
    r8_result = result_data.get('r8_extract_marker_result')
    if r8_result and r8_result.get('success'):
        summary['r8_marker_analysis']['analysis_available'] = True
        
        if r8_result.get('parsed_marker'):
            marker_data = r8_result['parsed_marker']
            # Check if marker was found by looking for marker_type field (successful parsing)
            # or explicit marker_found field (when no marker found)
            marker_found = marker_data.get('marker_type') is not None and marker_data.get('marker_type') != ''
            
            summary['r8_marker_analysis']['marker_found'] = marker_found
            
            if marker_found:
                summary['r8_marker_analysis']['marker_status'] = 'R8/D8/L8 marker found'
                summary['r8_marker_analysis']['compilation_details'] = {
                    'compilation_mode': marker_data.get('compilation-mode'),
                    'has_checksums': marker_data.get('has-checksums'),
                    'min_api': marker_data.get('min-api'),
                    'r8_mode': marker_data.get('r8-mode'),
                    'marker_type': marker_data.get('marker_type')
                }
            else:
                summary['r8_marker_analysis']['marker_status'] = 'No R8/D8/L8 marker found, Possibly a custom obfuscator (Arxan or DexGuard)'
        else:
            summary['r8_marker_analysis']['marker_found'] = False
            summary['r8_marker_analysis']['marker_status'] = 'Marker analysis failed'
    
    return summary

def create_final_dual_analysis_summary(detailed_results):
    """Create final dual analysis summary by aggregating all DEX file analyses
    
    COMMENTED OUT - TO BE REPLACED WITH NEW OBFUSCATION METHODS
    
    This function was responsible for aggregating individual DEX analysis results
    into a comprehensive summary for APK-level decision making.
    """
    # try:
    #     final_summary = {
    #         'total_dex_files': len(detailed_results),
    #         'aggregated_analysis': {
    #             'yara_strict': { ... },
    #             'manual_inspection': { ... },
    #             'effectiveness_gap': { ... }
    #         },
    #         'apk_level_decision': { ... },
    #         'per_dex_summary': []
    #     }
    #     ... extensive aggregation logic ...
    #     return final_summary
    # except Exception as e:
    #     return {
    #         'parse_error': f'Failed to create final dual analysis summary: {e}',
    #         'total_dex_files': len(detailed_results) if detailed_results else 0
    #     }
    
    # Placeholder return for commented out function
    return {
        'total_dex_files': len(detailed_results) if detailed_results else 0,
        'aggregated_analysis': {
            'yara_strict': {'should_trigger': False},
            'manual_inspection': {'should_trigger': False},
            'effectiveness_gap': {'overall_agreement': 'DISABLED'}
        },
        'apk_level_decision': {
            'yara_strict_final_trigger': False,
            'manual_inspection_final_trigger': False,
            'final_agreement': 'DISABLED'
        },
        'per_dex_summary': [],
        'parse_note': 'Final dual analysis summary is currently disabled - to be replaced with new methods'
    }
    try:
        final_summary = {
            'total_dex_files': len(detailed_results),
            'aggregated_analysis': {
                'yara_strict': {
                    'total_classes': 0,
                    'logical_classes': 0,
                    'short_strings': 0,
                    'single_classes': 0,
                    'two_digit_classes': 0,
                    'three_char_classes': 0,
                    'single_methods': 0,
                    'methods_passed': [],
                    'methods_failed': [],
                    'methods_passed_count': 0,
                    'should_trigger': False,
                    'triggering_dex_files': [],
                    'method_summary': {
                        'Method_1_Short_strings': {'passed_count': 0, 'dex_files': []},
                        'Method_2_Single_classes': {'passed_count': 0, 'dex_files': []},
                        'Method_3_Two_char_classes': {'passed_count': 0, 'dex_files': []},
                        'Method_3b_Three_char_classes': {'passed_count': 0, 'dex_files': []},
                        'Method_4_Single_methods': {'passed_count': 0, 'dex_files': []},
                        'Method_5_Combined_extreme': {'passed_count': 0, 'dex_files': []}
                    }
                },
                'manual_inspection': {
                    'total_classes': 0,
                    'logical_classes': 0,
                    'non_discovered_sdk_classes': 0,
                    'zebra_symbol_classes': 0,
                    'short_strings': 0,
                    'single_classes': 0,
                    'two_digit_classes': 0,
                    'three_char_classes': 0,
                    'single_methods': 0,
                    'methods_passed': [],
                    'methods_failed': [],
                    'methods_passed_count': 0,
                    'should_trigger': False,
                    'triggering_dex_files': [],
                    'method_summary': {
                        'Method_1_Short_strings': {'passed_count': 0, 'dex_files': []},
                        'Method_2_Single_classes': {'passed_count': 0, 'dex_files': []},
                        'Method_3_Two_char_classes': {'passed_count': 0, 'dex_files': []},
                        'Method_3b_Three_char_classes': {'passed_count': 0, 'dex_files': []},
                        'Method_4_Single_methods': {'passed_count': 0, 'dex_files': []},
                        'Method_5_Combined_extreme': {'passed_count': 0, 'dex_files': []}
                    }
                },
                'effectiveness_gap': {
                    'total_short_strings_ratio': 0.0,
                    'total_single_classes_ratio': 0.0,
                    'total_two_digit_ratio': 0.0,
                    'total_three_char_ratio': 0.0,
                    'total_single_method_ratio': 0.0,
                    'overall_methods_gap': 0,
                    'overall_agreement': 'UNKNOWN',
                    'consistency_across_dex': 0.0
                }
            },
            'apk_level_decision': {
                'yara_strict_final_trigger': False,
                'manual_inspection_final_trigger': False,
                'final_agreement': 'UNKNOWN',
                'triggering_rationale': {
                    'yara_strict': '',
                    'manual_inspection': ''
                }
            },
            'per_dex_summary': []
        }
        
        # Aggregate data from all DEX files
        total_yara_short_strings = 0
        total_manual_short_strings = 0
        total_yara_two_digit = 0
        total_manual_two_digit = 0
        total_yara_methods = 0
        total_manual_methods = 0
        
        consistent_agreements = 0
        
        for dex_result in detailed_results:
            if 'dual_analysis' not in dex_result:
                continue
                
            dex_name = dex_result.get('dex_name', 'unknown')
            dual_analysis = dex_result['dual_analysis']
            
            # Aggregate YARA-strict data
            yara_data = dual_analysis['yara_strict']
            final_summary['aggregated_analysis']['yara_strict']['total_classes'] += yara_data.get('total_classes', 0)
            final_summary['aggregated_analysis']['yara_strict']['logical_classes'] += yara_data.get('logical_classes', 0)
            final_summary['aggregated_analysis']['yara_strict']['short_strings'] += yara_data.get('short_strings', 0)
            final_summary['aggregated_analysis']['yara_strict']['single_classes'] += yara_data.get('single_classes', 0)
            final_summary['aggregated_analysis']['yara_strict']['two_digit_classes'] += yara_data.get('two_digit_classes', 0)
            final_summary['aggregated_analysis']['yara_strict']['three_char_classes'] += yara_data.get('three_char_classes', 0)
            final_summary['aggregated_analysis']['yara_strict']['single_methods'] += yara_data.get('single_methods', 0)
            
            # Track methods passed per DEX for YARA
            for method in yara_data.get('methods_passed', []):
                if method in final_summary['aggregated_analysis']['yara_strict']['method_summary']:
                    final_summary['aggregated_analysis']['yara_strict']['method_summary'][method]['passed_count'] += 1
                    final_summary['aggregated_analysis']['yara_strict']['method_summary'][method]['dex_files'].append(dex_name)
            
            if yara_data.get('should_trigger', False):
                final_summary['aggregated_analysis']['yara_strict']['triggering_dex_files'].append(dex_name)
            
            # Aggregate manual inspection data
            manual_data = dual_analysis['manual_inspection']
            final_summary['aggregated_analysis']['manual_inspection']['total_classes'] += manual_data.get('total_classes', 0)
            final_summary['aggregated_analysis']['manual_inspection']['logical_classes'] += manual_data.get('logical_classes', 0)
            final_summary['aggregated_analysis']['manual_inspection']['non_discovered_sdk_classes'] += manual_data.get('non_discovered_sdk_classes', 0)
            final_summary['aggregated_analysis']['manual_inspection']['zebra_symbol_classes'] += manual_data.get('zebra_symbol_classes', 0)
            final_summary['aggregated_analysis']['manual_inspection']['short_strings'] += manual_data.get('short_strings', 0)
            final_summary['aggregated_analysis']['manual_inspection']['single_classes'] += manual_data.get('single_classes', 0)
            final_summary['aggregated_analysis']['manual_inspection']['two_digit_classes'] += manual_data.get('two_digit_classes', 0)
            final_summary['aggregated_analysis']['manual_inspection']['three_char_classes'] += manual_data.get('three_char_classes', 0)
            final_summary['aggregated_analysis']['manual_inspection']['single_methods'] += manual_data.get('single_methods', 0)
            
            # Track methods passed per DEX for manual inspection
            for method in manual_data.get('methods_passed', []):
                if method in final_summary['aggregated_analysis']['manual_inspection']['method_summary']:
                    final_summary['aggregated_analysis']['manual_inspection']['method_summary'][method]['passed_count'] += 1
                    final_summary['aggregated_analysis']['manual_inspection']['method_summary'][method]['dex_files'].append(dex_name)
            
            if manual_data.get('should_trigger', False):
                final_summary['aggregated_analysis']['manual_inspection']['triggering_dex_files'].append(dex_name)
            
            # Track totals for ratio calculations
            total_yara_short_strings += yara_data.get('short_strings', 0)
            total_manual_short_strings += manual_data.get('short_strings', 0)
            total_yara_two_digit += yara_data.get('two_digit_classes', 0)
            total_manual_two_digit += manual_data.get('two_digit_classes', 0)
            total_yara_methods += yara_data.get('single_methods', 0)
            total_manual_methods += manual_data.get('single_methods', 0)
            
            # Track consistency
            if dual_analysis['effectiveness_gap'].get('agreement') == 'CONSISTENT':
                consistent_agreements += 1
            
            # Add per-DEX summary
            final_summary['per_dex_summary'].append({
                'dex_name': dex_name,
                'dex_size_bytes': dex_result.get('dex_size_bytes', 0),
                'yara_trigger': yara_data.get('should_trigger', False),
                'manual_trigger': manual_data.get('should_trigger', False),
                'yara_methods_passed': len(yara_data.get('methods_passed', [])),
                'manual_methods_passed': len(manual_data.get('methods_passed', [])),
                'logical_classes': manual_data.get('logical_classes', 0),
                'non_discovered_sdk_classes': manual_data.get('non_discovered_sdk_classes', 0),
                'zebra_symbol_classes': manual_data.get('zebra_symbol_classes', 0),
                'agreement': dual_analysis['effectiveness_gap'].get('agreement', 'UNKNOWN'),
                'two_digit_ratio': dual_analysis['effectiveness_gap'].get('two_digit_ratio', 0.0)
            })
        
        # Calculate aggregated effectiveness ratios
        if total_yara_short_strings > 0:
            final_summary['aggregated_analysis']['effectiveness_gap']['total_short_strings_ratio'] = total_manual_short_strings / total_yara_short_strings
        else:
            final_summary['aggregated_analysis']['effectiveness_gap']['total_short_strings_ratio'] = float('inf') if total_manual_short_strings > 0 else 0.0
        
        if total_yara_two_digit > 0:
            final_summary['aggregated_analysis']['effectiveness_gap']['total_two_digit_ratio'] = total_manual_two_digit / total_yara_two_digit
        else:
            final_summary['aggregated_analysis']['effectiveness_gap']['total_two_digit_ratio'] = float('inf') if total_manual_two_digit > 0 else 0.0
        
        if total_yara_methods > 0:
            final_summary['aggregated_analysis']['effectiveness_gap']['total_single_method_ratio'] = total_manual_methods / total_yara_methods
        else:
            final_summary['aggregated_analysis']['effectiveness_gap']['total_single_method_ratio'] = float('inf') if total_manual_methods > 0 else 0.0
        
        # Calculate consistency across DEX files
        if len(detailed_results) > 0:
            final_summary['aggregated_analysis']['effectiveness_gap']['consistency_across_dex'] = consistent_agreements / len(detailed_results)
        
        # Determine overall agreement
        if final_summary['aggregated_analysis']['effectiveness_gap']['consistency_across_dex'] >= 0.8:
            final_summary['aggregated_analysis']['effectiveness_gap']['overall_agreement'] = 'CONSISTENT'
        elif final_summary['aggregated_analysis']['effectiveness_gap']['consistency_across_dex'] >= 0.5:
            final_summary['aggregated_analysis']['effectiveness_gap']['overall_agreement'] = 'MIXED'
        else:
            final_summary['aggregated_analysis']['effectiveness_gap']['overall_agreement'] = 'INCONSISTENT'
        
        # Apply APK-level decision logic (similar to YARA rule logic)
        # APK should trigger if ANY DEX file would trigger the rule
        yara_should_trigger = len(final_summary['aggregated_analysis']['yara_strict']['triggering_dex_files']) > 0
        manual_should_trigger = len(final_summary['aggregated_analysis']['manual_inspection']['triggering_dex_files']) > 0
        
        final_summary['apk_level_decision']['yara_strict_final_trigger'] = yara_should_trigger
        final_summary['apk_level_decision']['manual_inspection_final_trigger'] = manual_should_trigger
        
        if yara_should_trigger == manual_should_trigger:
            final_summary['apk_level_decision']['final_agreement'] = 'CONSISTENT'
        else:
            final_summary['apk_level_decision']['final_agreement'] = 'DIFFERENT'
        
        # Create rationale
        if yara_should_trigger:
            final_summary['apk_level_decision']['triggering_rationale']['yara_strict'] = f"Triggered by {len(final_summary['aggregated_analysis']['yara_strict']['triggering_dex_files'])} DEX file(s): {', '.join(final_summary['aggregated_analysis']['yara_strict']['triggering_dex_files'])}"
        else:
            final_summary['apk_level_decision']['triggering_rationale']['yara_strict'] = "No DEX files triggered the YARA-strict rule"
        
        if manual_should_trigger:
            final_summary['apk_level_decision']['triggering_rationale']['manual_inspection'] = f"Triggered by {len(final_summary['aggregated_analysis']['manual_inspection']['triggering_dex_files'])} DEX file(s): {', '.join(final_summary['aggregated_analysis']['manual_inspection']['triggering_dex_files'])}"
        else:
            final_summary['apk_level_decision']['triggering_rationale']['manual_inspection'] = "No DEX files triggered the manual inspection rule"
        
        # Set final aggregated results
        final_summary['aggregated_analysis']['yara_strict']['should_trigger'] = yara_should_trigger
        final_summary['aggregated_analysis']['manual_inspection']['should_trigger'] = manual_should_trigger
        
        # Calculate overall methods gap
        total_yara_methods_passed = sum(method_data['passed_count'] for method_data in final_summary['aggregated_analysis']['yara_strict']['method_summary'].values())
        total_manual_methods_passed = sum(method_data['passed_count'] for method_data in final_summary['aggregated_analysis']['manual_inspection']['method_summary'].values())
        final_summary['aggregated_analysis']['effectiveness_gap']['overall_methods_gap'] = total_manual_methods_passed - total_yara_methods_passed
        
        return final_summary
        
    except Exception as e:
        return {
            'parse_error': f'Failed to create final dual analysis summary: {e}',
            'total_dex_files': len(detailed_results) if detailed_results else 0
        }
def format_dual_analysis_summary(parsed_result):
    """Format dual analysis summary for improved readability"""
    if 'dual_analysis' not in parsed_result:
        return "\n❌ No dual analysis data available\n"
    
    dual = parsed_result['dual_analysis']
    
    output = [
        "\n" + "="*80,
        "📊 DUAL ANALYSIS EFFECTIVENESS COMPARISON",
        "="*80,
        "",
        "📈 YARA-STRICT DETECTION:",
        f"   Two-digit classes: {dual['yara_strict']['two_digit_classes']:,}",
        f"   Single methods: {dual['yara_strict']['single_methods']:,}",
        f"   Methods passed: {dual['yara_strict']['methods_passed']}/4",
        f"   Rule triggers: {'🔴 YES' if dual['yara_strict']['should_trigger'] else '🟢 NO'}",
        "",
        "🔍 MANUAL INSPECTION DETECTION:",
        f"   Two-digit classes: {dual['manual_inspection']['two_digit_classes']:,}",
        f"   Single methods: {dual['manual_inspection']['single_methods']:,}",
        f"   Methods passed: {dual['manual_inspection']['methods_passed']}/4",
        f"   Rule triggers: {'🔴 YES' if dual['manual_inspection']['should_trigger'] else '🟢 NO'}",
        "",
        "⚖️ EFFECTIVENESS COMPARISON:",
        f"   Two-digit class ratio: {dual['effectiveness_gap']['two_digit_ratio']:.2f}x",
        f"   Method detection ratio: {dual['effectiveness_gap']['single_method_ratio']:.2f}x",
        f"   Agreement: {dual['effectiveness_gap']['agreement']}",
        "",
        "🎯 KEY INSIGHTS:"
    ]
    
    # Add insights based on the data
    yara_classes = dual['yara_strict']['two_digit_classes']
    manual_classes = dual['manual_inspection']['two_digit_classes']
    ratio = dual['effectiveness_gap']['two_digit_ratio']
    
    if ratio > 10:
        output.append(f"   • Manual inspection finds {ratio:.1f}x more obfuscated classes")
        output.append("   • YARA patterns have significant detection limitations")
    elif ratio > 2:
        output.append(f"   • Manual inspection moderately outperforms YARA ({ratio:.1f}x)")
    elif ratio == 1:
        output.append("   • Both methods show equivalent detection rates")
    
    if dual['effectiveness_gap']['agreement'] == 'DIFFERENT':
        output.append("   • Methods disagree on final rule triggering")
        output.append("   • Consider manual inspection for comprehensive analysis")
    else:
        output.append("   • Both methods agree on final rule triggering")
    
    if manual_classes > 1000:
        output.append(f"   • High obfuscation detected: {manual_classes:,} two-digit classes")
    
    output.append("="*80 + "\n")
    
    return "\n".join(output)
    if 'dual_analysis' not in parsed_result:
        return "\n❌ No dual analysis data available\n"
    
    dual = parsed_result['dual_analysis']
    
    output = [
        "\n" + "="*80,
        "📊 DUAL ANALYSIS EFFECTIVENESS COMPARISON",
        "="*80,
        "",
        "📈 YARA-STRICT DETECTION:",
        f"   Two-digit classes: {dual['yara_strict']['two_digit_classes']:,}",
        f"   Single methods: {dual['yara_strict']['single_methods']:,}",
        f"   Methods passed: {dual['yara_strict']['methods_passed']}/4",
        f"   Rule triggers: {'🔴 YES' if dual['yara_strict']['should_trigger'] else '🟢 NO'}",
        "",
        "🔍 MANUAL INSPECTION DETECTION:",
        f"   Two-digit classes: {dual['manual_inspection']['two_digit_classes']:,}",
        f"   Single methods: {dual['manual_inspection']['single_methods']:,}",
        f"   Methods passed: {dual['manual_inspection']['methods_passed']}/4",
        f"   Rule triggers: {'🔴 YES' if dual['manual_inspection']['should_trigger'] else '🟢 NO'}",
        "",
        "⚖️ EFFECTIVENESS COMPARISON:",
        f"   Two-digit class ratio: {dual['effectiveness_gap']['two_digit_ratio']:.2f}x",
        f"   Method detection ratio: {dual['effectiveness_gap']['single_method_ratio']:.2f}x",
        f"   Agreement: {dual['effectiveness_gap']['agreement']}",
        "",
        "🎯 KEY INSIGHTS:"
    ]
    
    # Add insights based on the data
    yara_classes = dual['yara_strict']['two_digit_classes']
    manual_classes = dual['manual_inspection']['two_digit_classes']
    ratio = dual['effectiveness_gap']['two_digit_ratio']
    
    if ratio > 10:
        output.append(f"   • Manual inspection finds {ratio:.1f}x more obfuscated classes")
        output.append("   • YARA patterns have significant detection limitations")
    elif ratio > 2:
        output.append(f"   • Manual inspection moderately outperforms YARA ({ratio:.1f}x)")
    elif ratio == 1:
        output.append("   • Both methods show equivalent detection rates")
    
    if dual['effectiveness_gap']['agreement'] == 'DIFFERENT':
        output.append("   • Methods disagree on final rule triggering")
        output.append("   • Consider manual inspection for comprehensive analysis")
    else:
        output.append("   • Both methods agree on final rule triggering")
    
    if manual_classes > 1000:
        output.append(f"   • High obfuscation detected: {manual_classes:,} two-digit classes")
    
    output.append("="*80 + "\n")
    
    return "\n".join(output)


def format_comprehensive_dual_analysis_summary(parsed_result):
    """Format comprehensive dual analysis summary with all pattern types
    
    COMMENTED OUT - TO BE REPLACED WITH NEW OBFUSCATION METHODS
    """
    # if 'dual_analysis' not in parsed_result:
    #     return "\n❌ No comprehensive dual analysis data available\n"
    # ... extensive formatting logic ...
    # return "\n".join(output)
    
    # Placeholder return for commented out function
    return "\n❌ Comprehensive dual analysis formatting is currently disabled - to be replaced with new methods\n"
    if 'dual_analysis' not in parsed_result:
        return "\n❌ No comprehensive dual analysis data available\n"
    
    dual = parsed_result['dual_analysis']
    effectiveness = dual['effectiveness_gap']
    
    output = [
        "\n" + "="*85,
        "📊 COMPREHENSIVE DUAL ANALYSIS EFFECTIVENESS COMPARISON",
        "="*85,
        "",
        "📈 YARA-STRICT DETECTION RESULTS:",
        f"   Total classes:       {dual['yara_strict']['total_classes']:,}",
        f"   Logical classes:     {dual['yara_strict']['logical_classes']:,}",
        f"   Two-digit classes:   {dual['yara_strict']['two_digit_classes']:,}",
        f"   Single methods:      {dual['yara_strict']['single_methods']:,}",
        f"   Methods passed:      {dual['yara_strict']['methods_passed']}/4",
        f"   Rule triggers:       {'🔴 YES' if dual['yara_strict']['should_trigger'] else '🟢 NO'}",
        "",
        "🔍 MANUAL INSPECTION DETECTION RESULTS:",
        f"   Total classes:       {dual['manual_inspection']['total_classes']:,}",
        f"   Logical classes:     {dual['manual_inspection']['logical_classes']:,}",
        f"   Two-digit classes:   {dual['manual_inspection']['two_digit_classes']:,}",
        f"   Single methods:      {dual['manual_inspection']['single_methods']:,}",
        f"   Methods passed:      {dual['manual_inspection']['methods_passed']}/4",
        f"   Rule triggers:       {'🔴 YES' if dual['manual_inspection']['should_trigger'] else '🟢 NO'}",
        "",
        "⚖️ PATTERN-BY-PATTERN EFFECTIVENESS COMPARISON:",
        f"   📊 Short strings ratio:    {effectiveness.get('short_strings_ratio', 0):.1f}x (gap: {effectiveness.get('short_strings_gap', 0):,})",
        f"   📊 Single classes ratio:   {effectiveness.get('single_classes_ratio', 0):.1f}x (gap: {effectiveness.get('single_classes_gap', 0):,})",
        f"   📊 Two-digit classes ratio: {effectiveness.get('two_digit_ratio', 0):.1f}x (gap: {effectiveness.get('two_digit_gap', 0):,})",
        f"   📊 Three-char classes ratio: {effectiveness.get('three_char_ratio', 0):.1f}x (gap: {effectiveness.get('three_char_gap', 0):,})",
        f"   📊 Single methods ratio:   {effectiveness.get('single_method_ratio', 0):.1f}x (gap: {effectiveness.get('single_methods_gap', 0):,})",
        f"   📊 Overall agreement:      {effectiveness.get('agreement', 'UNKNOWN')}",
        "",
        "🎯 COMPREHENSIVE INSIGHTS:"
    ]
    
    # Add insights based on all pattern types
    patterns = [
        ('Short strings', effectiveness.get('short_strings_ratio', 0), effectiveness.get('short_strings_gap', 0)),
        ('Single classes', effectiveness.get('single_classes_ratio', 0), effectiveness.get('single_classes_gap', 0)),
        ('Two-digit classes', effectiveness.get('two_digit_ratio', 0), effectiveness.get('two_digit_gap', 0)),
        ('Three-char classes', effectiveness.get('three_char_ratio', 0), effectiveness.get('three_char_gap', 0)),
        ('Single methods', effectiveness.get('single_method_ratio', 0), effectiveness.get('single_methods_gap', 0))
    ]
    
    # Find the most significant gaps
    biggest_gaps = sorted(patterns, key=lambda x: x[2], reverse=True)[:3]
    highest_ratios = sorted(patterns, key=lambda x: x[1], reverse=True)[:3]
    
    output.append("   🔍 Most Significant Detection Gaps:")
    for i, (pattern_name, ratio, gap) in enumerate(biggest_gaps, 1):
        if gap > 0:
            output.append(f"   {i}. {pattern_name}: {gap:,} patterns missed (ratio: {ratio:.1f}x)")
    
    output.append("")
    output.append("   📈 Highest Manual vs YARA Ratios:")
    for i, (pattern_name, ratio, gap) in enumerate(highest_ratios, 1):
        if ratio > 1:
            output.append(f"   {i}. {pattern_name}: {ratio:.1f}x more detected by manual inspection")
    
    # Overall assessment
    output.append("")
    total_manual = dual['manual_inspection']['two_digit_classes']
    total_yara = dual['yara_strict']['two_digit_classes']
    if total_manual > 1000:
        output.append(f"   ⚠️  High obfuscation detected: {total_manual:,} classes found by manual inspection")
    
    if effectiveness.get('agreement', 'DIFFERENT') == 'DIFFERENT':
        output.append("   ⚠️  Methods disagree on final rule triggering")
        output.append("   💡 Recommendation: Use manual inspection for comprehensive analysis")
    else:
        output.append("   ✅ Both methods agree on final rule triggering")
    
    output.append("="*85 + "\n")
    
    return "\n".join(output)


def analyze_single_apk(apk_path, r8_jar_path, include_comprehensive=False, sdk_config=None):
    """Analyze a single APK with available tools"""
    apk_name = os.path.basename(apk_path)
    apk_size = os.path.getsize(apk_path) / (1024*1024)
    
    print(f"\nAnalyzing: {apk_name} ({apk_size:.1f} MB)")
    
    # Extract package name for metadata
    package_name = extract_package_name(apk_path)
    
    result_data = {
        'apk_name': apk_name,
        'apk_path': apk_path,
        'apk_size_mb': apk_size,
        'package_name': package_name
    }
    
    # Check if SDK configuration is available for this package
    package_config = None
    if sdk_config and package_name:
        package_config = get_package_sdk_config(package_name, sdk_config)
        if package_config:
            print(f"📦 Found SDK configuration for package: {package_name}")
            print(f"   📋 Custom SDK classes: {len(package_config['sdk_classes'])}")
            print(f"   📋 Custom legitimate classes: {len(package_config['legitimate_classes'])}")
            result_data['used_sdk_config'] = True
            result_data['sdk_config_summary'] = {
                'sdk_classes_count': len(package_config['sdk_classes']),
                'legitimate_classes_count': len(package_config['legitimate_classes']),
                'config_patterns': {
                    'sdk_classes': package_config['sdk_classes'][:5],  # Show first 5 patterns
                    'legitimate_classes': package_config['legitimate_classes'][:5]
                }
            }
        else:
            print(f"📦 No SDK configuration found for package: {package_name}")
            result_data['used_sdk_config'] = False
    else:
        result_data['used_sdk_config'] = False
    
    # Run APKiD using module approach (confirmed working)
    apkid_result = run_command_with_timeout(
        [sys.executable, '-m', 'apkid', '-j', apk_path],
        timeout=30  # Increased timeout for better reliability
    )
    
    # Parse APKiD JSON output into structured data
    if apkid_result['success'] and apkid_result['stdout']:
        apkid_result['parsed_output'] = parse_apkid_json_output(apkid_result['stdout'])
    else:
        apkid_result['parsed_output'] = None
    
    result_data['apkid_result'] = apkid_result
    
    # Run R8 ExtractMarker with short timeout (if R8 jar is available)
    if r8_jar_path and os.path.exists(r8_jar_path):
        r8_result = run_command_with_timeout(
            ['java', '-cp', r8_jar_path, 'com.android.tools.r8.ExtractMarker', apk_path],
            timeout=10  # Very short timeout
        )
        
        # Parse R8 marker output into structured JSON
        if r8_result['success'] and r8_result['stdout']:
            r8_result['parsed_marker'] = parse_r8_marker_output(r8_result['stdout'])
        else:
            r8_result['parsed_marker'] = None
        
        result_data['r8_extract_marker_result'] = r8_result
    
    # Run comprehensive massive obfuscation test if requested
    if include_comprehensive:
        comprehensive_result = run_comprehensive_massive_obf_test(
            apk_path, 
            timeout=45, 
            package_name=package_name, 
            sdk_config=sdk_config
        )
        result_data['comprehensive_massive_obf_result'] = comprehensive_result
        
        # Create comprehensive final summary
        result_data['comprehensive_final_summary'] = create_comprehensive_final_summary(result_data)
    
    return result_data

def extract_package_name(apk_path):
    """Extract package name from APK using aapt or zipfile parsing"""
    try:
        # Try using aapt first (most reliable)
        try:
            result = subprocess.run(
                ['aapt', 'dump', 'badging', apk_path],
                capture_output=True,
                text=True,
                timeout=10,
                encoding='utf-8',
                errors='replace'  # Handle encoding issues
            )
            if result.returncode == 0 and result.stdout:
                # Fix: Check if stdout is not None before calling split
                stdout_lines = result.stdout.split('\n') if result.stdout else []
                for line in stdout_lines:
                    if line.startswith('package:'):
                        # Extract package name from line like: package: name='com.zebra.demo' versionCode='1' versionName='1.0'
                        match = re.search(r"name='([^']+)'", line)
                        if match:
                            return match.group(1)
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError, OSError):
            # Broader exception handling for subprocess issues
            pass
        
        # Fallback: Parse AndroidManifest.xml from APK using zipfile
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Check if AndroidManifest.xml exists
                if 'AndroidManifest.xml' not in apk_zip.namelist():
                    return None
                
                manifest_data = apk_zip.read('AndroidManifest.xml')
                
                # Look for com.zebra or com.symbol patterns in the binary data first
                zebra_match = re.search(rb'com\.zebra\.[a-zA-Z0-9_.]+', manifest_data)
                if zebra_match:
                    return zebra_match.group(0).decode('utf-8', errors='ignore')
                
                symbol_match = re.search(rb'com\.symbol\.[a-zA-Z0-9_.]+', manifest_data)
                if symbol_match:
                    return symbol_match.group(0).decode('utf-8', errors='ignore')
                
                # Look for general package patterns - more careful with decoding
                # Try to find common package name patterns in the binary data
                for pattern in [rb'[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*){2,}']:
                    matches = re.findall(pattern, manifest_data)
                    for match in matches:
                        try:
                            candidate = match.decode('utf-8', errors='ignore')
                            # Filter out common false positives and ensure it looks like a package name
                            if (len(candidate) > 5 and 
                                not candidate.startswith(('android.', 'java.', 'javax.', 'org.apache', 'com.android.')) and
                                candidate.count('.') >= 2 and
                                not any(char in candidate for char in [' ', '\n', '\t', '\r'])):
                                return candidate
                        except (UnicodeDecodeError, AttributeError):
                            continue
        except (zipfile.BadZipFile, zipfile.LargeZipFile, KeyError, OSError):
            # Handle corrupted or invalid APK files
            pass
        
        return None
        
    except Exception as e:
        print(f"    Warning: Could not extract package name from {os.path.basename(apk_path)}: {e}")
        return None

def is_zebra_package(package_name):
    """Check if package name starts with com.zebra or com.symbol"""
    if not package_name:
        return False
    return package_name.startswith('com.zebra') or package_name.startswith('com.symbol')

def main():
    parser = argparse.ArgumentParser(description='Quick APK Analysis with optional comprehensive obfuscation testing')
    parser.add_argument('directory', help='Directory to search for APK files')
    parser.add_argument('--r8-jar', default='r8.jar', help='Path to R8 JAR file (optional)')
    parser.add_argument('--output', default='quick_analysis_results.json', help='Output JSON file')
    parser.add_argument('--max-apks', type=int, default=None, help='Maximum number of APKs to analyze (default: analyze all APKs found)')
    parser.add_argument('--comprehensive', action='store_true', help='Include comprehensive massive obfuscation analysis (slower but detailed)')
    parser.add_argument('--comprehensive-only', action='store_true', help='Run only comprehensive obfuscation analysis (skip APKiD and R8)')
    parser.add_argument('--save-comprehensive-details', help='Save detailed comprehensive analysis results to separate file')
    parser.add_argument('--show-dual-analysis', action='store_true', help='Display dual analysis effectiveness comparison for each APK')
    parser.add_argument('--zebra-only', action='store_true', help='Only analyze APKs with package names starting with com.zebra or com.symbol')
    parser.add_argument('--sdk-config', help='Path to SDK configuration JSON file for package-specific SDK class definitions')
    
    args = parser.parse_args()
    
    # Load SDK configuration if provided
    sdk_config = None
    if args.sdk_config:
        print(f"Loading SDK configuration from: {args.sdk_config}")
        sdk_config = load_sdk_configuration(args.sdk_config)
        if sdk_config:
            print(f"✅ SDK configuration loaded successfully")
        else:
            print(f"❌ Failed to load SDK configuration, proceeding without it")
    
    # Validate inputs
    if not os.path.isdir(args.directory):
        print(f"Error: Directory '{args.directory}' does not exist.")
        return
    
    # R8 jar is optional now
    r8_jar_available = False
    if args.r8_jar and os.path.isfile(args.r8_jar):
        r8_jar_available = True
        print(f"R8 JAR found: {args.r8_jar}")
    else:
        if not args.comprehensive_only:
            print(f"Warning: R8 JAR file '{args.r8_jar}' not found. R8 analysis will be skipped.")
        args.r8_jar = None
    
    # If comprehensive-only is specified, we don't need R8
    if args.comprehensive_only:
        print("Running in comprehensive-only mode (APKiD and R8 analysis will be skipped)")
    
    # Check if comprehensive analysis script exists
    if args.comprehensive or args.comprehensive_only:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        comprehensive_script = os.path.join(script_dir, "comprehensive_massive_obf_test.py")
        if not os.path.exists(comprehensive_script):
            print(f"Error: comprehensive_massive_obf_test.py not found at {comprehensive_script}")
            print("Please ensure the comprehensive analysis script is in the same directory as this script.")
            return
        print(f"Comprehensive analysis script found: {comprehensive_script}")
    
    # Find APK files
    print(f"Searching for APK files in: {args.directory}")
    apk_files = []
    for root, dirs, files in os.walk(args.directory):
        for file in files:
            if file.lower().endswith('.apk'):
                apk_files.append(os.path.join(root, file))
                # Only break if max_apks is specified and limit is reached
                if args.max_apks is not None and len(apk_files) >= args.max_apks:
                    break
        # Only break if max_apks is specified and limit is reached
        if args.max_apks is not None and len(apk_files) >= args.max_apks:
            break
    
    # Store original count before filtering
    original_apk_count = len(apk_files)
    
    if not apk_files:
        print("No APK files found.")
        return
    
    # Filter for Zebra packages if requested
    if args.zebra_only:
        print("Filtering APKs for Zebra packages (com.zebra.* or com.symbol.*)...")
        zebra_apks = []
        skipped_count = 0
        
        for apk_path in apk_files:
            print(f"  Checking package name for: {os.path.basename(apk_path)}")
            package_name = extract_package_name(apk_path)
            
            if package_name:
                print(f"    Package: {package_name}")
                if is_zebra_package(package_name):
                    print(f"    ✅ Zebra package detected - including in analysis")
                    zebra_apks.append(apk_path)
                else:
                    print(f"    ❌ Not a Zebra package - skipping")
                    skipped_count += 1
            else:
                print(f"    ⚠️  Could not determine package name - skipping")
                skipped_count += 1
        
        print(f"\nZebra filtering results:")
        print(f"  Total APKs found: {len(apk_files)}")
        print(f"  Zebra APKs found: {len(zebra_apks)}")
        print(f"  APKs skipped: {skipped_count}")
        
        apk_files = zebra_apks
        
        if not apk_files:
            print("No Zebra packages found. Exiting.")
            return
    
    # Determine how many APKs to analyze
    apks_to_analyze = len(apk_files) if args.max_apks is None else min(len(apk_files), args.max_apks)
    
    if args.max_apks is None:
        print(f"Found {len(apk_files)} APK file(s) (analyzing all)")
    else:
        print(f"Found {len(apk_files)} APK file(s) (analyzing max {args.max_apks})")
    
    if args.comprehensive or args.comprehensive_only:
        print("Comprehensive massive obfuscation analysis enabled - this will take longer but provide detailed results")
    
    # Analyze APKs
    results = []
    comprehensive_details = []  # Store detailed comprehensive results separately
    for i, apk_path in enumerate(apk_files[:apks_to_analyze], 1):
        print(f"\n[{i}/{apks_to_analyze}]", end=" ")
        try:
            # Determine what analysis to run
            include_comprehensive = args.comprehensive or args.comprehensive_only
            
            if args.comprehensive_only:
                # Run only comprehensive analysis
                result = {
                    'apk_name': os.path.basename(apk_path),
                    'apk_path': apk_path,
                    'apk_size_mb': os.path.getsize(apk_path) / (1024*1024)
                }
                comprehensive_result = run_comprehensive_massive_obf_test(
                    apk_path, 
                    timeout=60, 
                    package_name=extract_package_name(apk_path), 
                    sdk_config=sdk_config
                )
                result['comprehensive_massive_obf_result'] = comprehensive_result
                
                # We need APKiD and R8 results for complete final summary, so run them for comprehensive-only mode too
                apkid_result = run_command_with_timeout(
                    [sys.executable, '-m', 'apkid', '-j', apk_path],
                    timeout=30
                )
                if apkid_result['success'] and apkid_result['stdout']:
                    apkid_result['parsed_output'] = parse_apkid_json_output(apkid_result['stdout'])
                else:
                    apkid_result['parsed_output'] = None
                result['apkid_result'] = apkid_result
                
                # Run R8 marker analysis if available
                if args.r8_jar and os.path.exists(args.r8_jar):
                    r8_result = run_command_with_timeout(
                        ['java', '-cp', args.r8_jar, 'com.android.tools.r8.ExtractMarker', apk_path],
                        timeout=10
                    )
                    if r8_result['success'] and r8_result['stdout']:
                        r8_result['parsed_marker'] = parse_r8_marker_output(r8_result['stdout'])
                    else:
                        r8_result['parsed_marker'] = None
                    result['r8_extract_marker_result'] = r8_result
                
                # Create comprehensive final summary
                result['comprehensive_final_summary'] = create_comprehensive_final_summary(result)
            else:
                # Run normal analysis with optional comprehensive
                result = analyze_single_apk(apk_path, args.r8_jar, include_comprehensive, sdk_config)
            
            results.append(result)
            
            # Extract comprehensive details for separate file if requested
            if args.save_comprehensive_details and 'comprehensive_massive_obf_result' in result:
                comp_result = result['comprehensive_massive_obf_result']
                if comp_result.get('success') and comp_result.get('parsed_analysis'):
                    comprehensive_details.append({
                        'apk_name': result['apk_name'],
                        'apk_path': result['apk_path'],
                        'comprehensive_analysis': comp_result['parsed_analysis'],
                        'full_output': comp_result.get('stdout', ''),
                        'execution_time': comp_result.get('execution_time', 0)
                    })
            
            # Display dual analysis summary if requested
            if args.show_dual_analysis and 'comprehensive_massive_obf_result' in result:
                comp_result = result['comprehensive_massive_obf_result']
                if comp_result.get('success') and comp_result.get('parsed_analysis'):
                    parsed_analysis = comp_result['parsed_analysis']
                    
                    # Show final dual analysis summary if available
                    if 'final_dual_analysis' in parsed_analysis:
                        print(f"\n🔍 FINAL DUAL ANALYSIS SUMMARY for {result['apk_name']}:")
                        
                        final_dual = parsed_analysis['final_dual_analysis']
                        apk_decision = final_dual.get('apk_level_decision', {})
                        aggregated = final_dual.get('aggregated_analysis', {})
                        
                        print(f"📊 APK-LEVEL DECISION:")
                        print(f"   YARA-strict final: {'🔴 TRIGGERS' if apk_decision.get('yara_strict_final_trigger', False) else '🟢 NO TRIGGER'}")
                        print(f"   Manual final: {'🔴 TRIGGERS' if apk_decision.get('manual_inspection_final_trigger', False) else '🟢 NO TRIGGER'}")
                        print(f"   Agreement: {apk_decision.get('final_agreement', 'UNKNOWN')}")
                        
                        if 'yara_strict' in aggregated and 'manual_inspection' in aggregated:
                            yara_agg = aggregated['yara_strict']
                            manual_agg = aggregated['manual_inspection']
                            gap = aggregated.get('effectiveness_gap', {})
                            
                            print(f"📈 AGGREGATED TOTALS:")
                            print(f"   YARA two-digit: {yara_agg.get('two_digit_classes', 0):,} | Manual: {manual_agg.get('two_digit_classes', 0):,}")
                            print(f"   YARA methods: {yara_agg.get('single_methods', 0):,} | Manual: {manual_agg.get('single_methods', 0):,}")
                            print(f"   Triggering DEX files: YARA={len(yara_agg.get('triggering_dex_files', []))} | Manual={len(manual_agg.get('triggering_dex_files', []))}")
                            
                            if gap.get('total_two_digit_ratio', 0) > 1:
                                print(f"⚖️ EFFECTIVENESS: Manual finds {gap['total_two_digit_ratio']:.1f}x more classes overall")
                        
                        print(f"📋 DEX FILES: {final_dual.get('total_dex_files', 0)} analyzed")
                        
                    # Fallback to original dual analysis if final not available
                    elif 'dual_analysis' in parsed_analysis:
                        dual = parsed_analysis['dual_analysis']
                        
                        print(f"\n🔍 DUAL ANALYSIS SUMMARY for {result['apk_name']}:")
                        
                        print(f"📈 YARA-STRICT: {dual['yara_strict']['two_digit_classes']:,} classes, " + 
                              f"{dual['yara_strict']['methods_passed']}/4 methods, " +
                              f"{'🔴 TRIGGERS' if dual['yara_strict']['should_trigger'] else '🟢 NO TRIGGER'}")
                        
                        print(f"🔍 MANUAL: {dual['manual_inspection']['two_digit_classes']:,} classes, " + 
                              f"{dual['manual_inspection']['methods_passed']}/4 methods, " +
                              f"{'🔴 TRIGGERS' if dual['manual_inspection']['should_trigger'] else '🟢 NO TRIGGER'}")
                        
                        gap = dual['effectiveness_gap']
                        if gap['two_digit_ratio'] > 1:
                            print(f"⚖️ EFFECTIVENESS: Manual finds {gap['two_digit_ratio']:.1f}x more classes | " + 
                                  f"Agreement: {gap['agreement']}")
                        else:
                            print(f"⚖️ EFFECTIVENESS: Equivalent detection | Agreement: {gap['agreement']}")
                        
                    print("-" * 80)
            
        except Exception as e:
            print(f"FAILED: {e}")
            results.append({
                'apk_name': os.path.basename(apk_path),
                'apk_path': apk_path,
                'error': str(e)
            })
    
    # Calculate summary statistics
    successful_apkid = sum(1 for r in results if r.get('apkid_result', {}).get('success', False))
    successful_r8 = sum(1 for r in results if r.get('r8_extract_marker_result', {}).get('success', False))
    successful_comprehensive = sum(1 for r in results if r.get('comprehensive_massive_obf_result', {}).get('success', False))
    
    # Count comprehensive analysis results for YARA Strict and Manual Investigation
    obfuscation_detected_by_yara_strict = 0
    obfuscation_detected_by_manual_investigation = 0
    obfuscation_not_detected_by_either = 0
    obfuscation_only_detected_by_yara_strict = 0
    obfuscation_only_detected_by_manual_investigation = 0
    
    for r in results:
        comp_result = r.get('comprehensive_massive_obf_result')
        if comp_result and comp_result.get('success') and comp_result.get('parsed_analysis'):
            
            # Get the comprehensive final summary for status information
            final_summary = r.get('comprehensive_final_summary', {})
            
            # Check YARA Strict status (FIXED: correct key name)
            yara_summary = final_summary.get('strict_yara_summary', {})
            yara_margin_status = yara_summary.get('margin_status', {})
            yara_detected = yara_margin_status.get('status', 'UNKNOWN') in ['OPTIMAL', 'MINIMAL', 'EXCEPTION_PASS']
            
            # Check Manual Investigation status  
            manual_summary = final_summary.get('manual_investigation_summary', {})
            manual_margin_status = manual_summary.get('margin_status', {})
            manual_detected = manual_margin_status.get('status', 'UNKNOWN') in ['OPTIMAL', 'MINIMAL', 'EXCEPTION_PASS']
            
            # Count detection patterns
            if yara_detected:
                obfuscation_detected_by_yara_strict += 1
            
            if manual_detected:
                obfuscation_detected_by_manual_investigation += 1
            
            if not yara_detected and not manual_detected:
                obfuscation_not_detected_by_either += 1
            
            if yara_detected and not manual_detected:
                obfuscation_only_detected_by_yara_strict += 1
            
            if manual_detected and not yara_detected:
                obfuscation_only_detected_by_manual_investigation += 1
    
    # Save main results
    output_data = {
        'analysis_summary': {
            'total_apks_found': original_apk_count,
            'total_apks_after_filtering': len(apk_files) if args.zebra_only else original_apk_count,
            'total_apks_analyzed': len(results),
            'search_directory': args.directory,
            'r8_jar_path': args.r8_jar,
            'zebra_only_mode': args.zebra_only,
            'comprehensive_analysis_enabled': args.comprehensive or args.comprehensive_only,
            'comprehensive_only_mode': args.comprehensive_only,
            'successful_apkid_scans': successful_apkid,
            'successful_r8_scans': successful_r8,
            'successful_comprehensive_scans': successful_comprehensive,
            'obfuscation_detected_by_yara_strict': obfuscation_detected_by_yara_strict,
            'obfuscation_detected_by_manual_investigation': obfuscation_detected_by_manual_investigation,
            'obfuscation_not_detected_by_either': obfuscation_not_detected_by_either,
            'obfuscation_only_detected_by_yara_strict': obfuscation_only_detected_by_yara_strict,
            'obfuscation_only_detected_by_manual_investigation': obfuscation_only_detected_by_manual_investigation
        },
        'results': results
    }
    
    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        print(f"\nMain results saved to: {args.output}")
    except Exception as e:
        print(f"Error saving main results: {e}")
    
    # Save comprehensive details to separate file if requested
    if args.save_comprehensive_details and comprehensive_details:
        try:
            with open(args.save_comprehensive_details, 'w', encoding='utf-8') as f:
                json.dump({
                    'comprehensive_analysis_details': {
                        'total_apks_with_comprehensive_analysis': len(comprehensive_details),
                        'analysis_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'script_version': 'enhanced_with_comprehensive_obf_analysis'
                    },
                    'detailed_results': comprehensive_details
                }, f, indent=2, ensure_ascii=False)
            print(f"Comprehensive analysis details saved to: {args.save_comprehensive_details}")
        except Exception as e:
            print(f"Error saving comprehensive details: {e}")
    
    # Print summary
    print(f"\nSummary:")
    if args.zebra_only:
        print(f"  APKs found (total): {original_apk_count}")
        print(f"  APKs found (zebra): {len(apk_files) if 'apk_files' in locals() else 0}")
        print(f"  APKs analyzed: {len(results)}")
    else:
        print(f"  APKs analyzed: {len(results)}")
    if not args.comprehensive_only:
        print(f"  Successful APKiD: {successful_apkid}")
        if args.r8_jar:
            print(f"  Successful R8: {successful_r8}")
    if args.comprehensive or args.comprehensive_only:
        print(f"  Successful comprehensive: {successful_comprehensive}")
        print(f"  Obfuscation detected by YARA Strict: {obfuscation_detected_by_yara_strict}")
        print(f"  Obfuscation detected by Manual Investigation: {obfuscation_detected_by_manual_investigation}")
        print(f"  Obfuscation not detected by either: {obfuscation_not_detected_by_either}")
        print(f"  Obfuscation only detected by YARA Strict: {obfuscation_only_detected_by_yara_strict}")
        print(f"  Obfuscation only detected by Manual Investigation: {obfuscation_only_detected_by_manual_investigation}")
        
        # Calculate percentage if we have comprehensive results
        if successful_comprehensive > 0:
            yara_detection_rate = (obfuscation_detected_by_yara_strict / successful_comprehensive) * 100
            manual_detection_rate = (obfuscation_detected_by_manual_investigation / successful_comprehensive) * 100
            no_detection_rate = (obfuscation_not_detected_by_either / successful_comprehensive) * 100
            yara_only_rate = (obfuscation_only_detected_by_yara_strict / successful_comprehensive) * 100
            manual_only_rate = (obfuscation_only_detected_by_manual_investigation / successful_comprehensive) * 100
            
            print(f"  YARA Strict detection rate: {yara_detection_rate:.1f}%")
            print(f"  Manual Investigation detection rate: {manual_detection_rate:.1f}%")
            print(f"  No detection rate: {no_detection_rate:.1f}%")
            print(f"  YARA Strict only detection rate: {yara_only_rate:.1f}%")
            print(f"  Manual Investigation only detection rate: {manual_only_rate:.1f}%")

if __name__ == '__main__':
    main()
