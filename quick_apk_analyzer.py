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

def run_comprehensive_massive_obf_test(apk_path, timeout=30):
    """Run comprehensive massive obfuscation test and return structured results"""
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
            'detailed_results': []
        }
        
        # Look for APKiD results
        if 'massive_name_obfuscation: 🔴 DETECTED' in stdout or 'massive_name_obfuscation: DETECTED' in stdout:
            data['apkid_detected_massive_obf'] = True
        elif 'massive_name_obfuscation: 🟢 NOT DETECTED' in stdout or 'massive_name_obfuscation: NOT DETECTED' in stdout:
            data['apkid_detected_massive_obf'] = False
        
        # Extract completion percentage
        import re
        percentage_pattern = r'Completion percentage:\s*(\d+\.?\d*)%'
        percentages = re.findall(percentage_pattern, stdout)
        if percentages:
            data['highest_completion_percentage'] = max(float(p) for p in percentages)
        
        # Look for highest percentage in different formats
        if data['highest_completion_percentage'] == 0.0:
            alt_percentage_pattern = r'Highest completion percentage:\s*(\d+\.?\d*)%'
            alt_percentages = re.findall(alt_percentage_pattern, stdout)
            if alt_percentages:
                data['highest_completion_percentage'] = float(alt_percentages[0])
        
        # Extract manual analysis result
        if 'Manual analysis result: 🔴 SHOULD TRIGGER' in stdout or 'SHOULD TRIGGER' in stdout:
            data['manual_analysis_result'] = 'SHOULD_TRIGGER'
        elif 'Manual analysis result: 🟢 SHOULD NOT TRIGGER' in stdout or 'SHOULD NOT TRIGGER' in stdout:
            data['manual_analysis_result'] = 'SHOULD_NOT_TRIGGER'
        
        # Extract consistency check
        if 'Consistency: ✅ Manual analysis matches APKiD result' in stdout or 'Manual analysis matches APKiD' in stdout:
            data['consistency_check'] = 'CONSISTENT'
        elif 'Consistency: ⚠️  Manual analysis differs from APKiD result' in stdout or 'differs from APKiD' in stdout:
            data['consistency_check'] = 'INCONSISTENT'
        
        # Count DEX files analyzed
        dex_count_pattern = r'Files analyzed:\s*(\d+)\s*DEX'
        dex_matches = re.findall(dex_count_pattern, stdout)
        if dex_matches:
            data['dex_files_analyzed'] = int(dex_matches[0])
        
        # Count DEX files analyzed
        dex_count_pattern = r'Files analyzed:\s*(\d+)\s*DEX'
        dex_matches = re.findall(dex_count_pattern, stdout)
        if dex_matches:
            data['dex_files_analyzed'] = int(dex_matches[0])
        
        # Extract final assessment agreement from main section
        if 'Agreement: ✅ CONSISTENT' in stdout:
            data['consistency_check'] = 'CONSISTENT'
        elif 'Agreement: ⚠️ DIFFERENT' in stdout:
            data['consistency_check'] = 'INCONSISTENT'
        
        # Extract individual DEX analysis results
        dex_sections = re.split(r'DETAILED ANALYSIS:', stdout)
        for section in dex_sections[1:]:  # Skip first split (before first DEX)
            dex_result = parse_individual_dex_result(section)
            if dex_result:
                data['detailed_results'].append(dex_result)
        
        # Create final_dual_analysis by summarizing all individual DEX analyses
        if data['detailed_results']:
            data['final_dual_analysis'] = create_final_dual_analysis_summary(data['detailed_results'])
        
        return data
        
    except Exception as e:
        return {
            'parse_error': f'Failed to parse comprehensive obf output: {e}',
            'raw_output_sample': stdout[:1000] + ('...' if len(stdout) > 1000 else '')
        }

def parse_individual_dex_result(section):
    """Parse individual DEX analysis section with comprehensive dual analysis"""
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
        
        # Extract YARA-STRICT Analysis data
        yara_section = re.search(r'📊 YARA-STRICT Analysis.*?───────────────────────────────────────────────(.*?)📋 MANUAL INSPECTION Analysis', section, re.DOTALL)
        if yara_section:
            yara_data = yara_section.group(1)
            
            # Extract YARA counts
            yara_total_match = re.search(r'Total classes \(L\.\.\.;\):\s*([0-9,]+)', yara_data)
            if yara_total_match:
                result['dual_analysis']['yara_strict']['total_classes'] = int(yara_total_match.group(1).replace(',', ''))
            
            yara_logical_match = re.search(r'Logical classes:\s*([0-9,]+)', yara_data)
            if yara_logical_match:
                result['dual_analysis']['yara_strict']['logical_classes'] = int(yara_logical_match.group(1).replace(',', ''))
            
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
        
        return result
        
    except Exception as e:
        return {
            'parse_error': f'Failed to parse individual DEX result: {e}',
            'raw_section_sample': section[:500] + ('...' if len(section) > 500 else '')
        }


def create_final_dual_analysis_summary(detailed_results):
    """Create final dual analysis summary by aggregating all DEX file analyses"""
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


def format_comprehensive_dual_analysis_summary(parsed_result):
    """Format comprehensive dual analysis summary with all pattern types"""
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


def analyze_single_apk(apk_path, r8_jar_path, include_comprehensive=False):
    """Analyze a single APK with available tools"""
    apk_name = os.path.basename(apk_path)
    apk_size = os.path.getsize(apk_path) / (1024*1024)
    
    print(f"\nAnalyzing: {apk_name} ({apk_size:.1f} MB)")
    
    result_data = {
        'apk_name': apk_name,
        'apk_path': apk_path,
        'apk_size_mb': apk_size
    }
    
    # Run APKiD with timeout
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
        comprehensive_result = run_comprehensive_massive_obf_test(apk_path, timeout=45)
        result_data['comprehensive_massive_obf_result'] = comprehensive_result
    
    return result_data

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
    
    args = parser.parse_args()
    
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
    
    if not apk_files:
        print("No APK files found.")
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
                comprehensive_result = run_comprehensive_massive_obf_test(apk_path, timeout=60)
                result['comprehensive_massive_obf_result'] = comprehensive_result
            else:
                # Run normal analysis with optional comprehensive
                result = analyze_single_apk(apk_path, args.r8_jar, include_comprehensive)
            
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
    
    # Count comprehensive analysis results
    massive_obf_detected_apkid = 0
    massive_obf_detected_manual = 0
    consistent_results = 0
    
    for r in results:
        comp_result = r.get('comprehensive_massive_obf_result')
        if comp_result and comp_result.get('success') and comp_result.get('parsed_analysis'):
            analysis = comp_result['parsed_analysis']
            if analysis.get('apkid_detected_massive_obf'):
                massive_obf_detected_apkid += 1
            if analysis.get('manual_analysis_result') == 'SHOULD_TRIGGER':
                massive_obf_detected_manual += 1
            if analysis.get('consistency_check') == 'CONSISTENT':
                consistent_results += 1
    
    # Save main results
    output_data = {
        'analysis_summary': {
            'total_apks_found': len(apk_files),
            'total_apks_analyzed': len(results),
            'search_directory': args.directory,
            'r8_jar_path': args.r8_jar,
            'comprehensive_analysis_enabled': args.comprehensive or args.comprehensive_only,
            'comprehensive_only_mode': args.comprehensive_only,
            'successful_apkid_scans': successful_apkid,
            'successful_r8_scans': successful_r8,
            'successful_comprehensive_scans': successful_comprehensive,
            'massive_obf_detected_by_apkid': massive_obf_detected_apkid,
            'massive_obf_detected_by_manual_analysis': massive_obf_detected_manual,
            'consistent_apkid_vs_manual_results': consistent_results
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
    print(f"  APKs analyzed: {len(results)}")
    if not args.comprehensive_only:
        print(f"  Successful APKiD: {successful_apkid}")
        if args.r8_jar:
            print(f"  Successful R8: {successful_r8}")
    if args.comprehensive or args.comprehensive_only:
        print(f"  Successful comprehensive: {successful_comprehensive}")
        print(f"  Massive obfuscation detected (APKiD): {massive_obf_detected_apkid}")
        print(f"  Massive obfuscation detected (manual): {massive_obf_detected_manual}")
        print(f"  Consistent APKiD vs manual: {consistent_results}")
        
        # Calculate percentage if we have comprehensive results
        if successful_comprehensive > 0:
            detection_rate_apkid = (massive_obf_detected_apkid / successful_comprehensive) * 100
            detection_rate_manual = (massive_obf_detected_manual / successful_comprehensive) * 100
            consistency_rate = (consistent_results / successful_comprehensive) * 100
            print(f"  Detection rate (APKiD): {detection_rate_apkid:.1f}%")
            print(f"  Detection rate (manual): {detection_rate_manual:.1f}%")
            print(f"  Consistency rate: {consistency_rate:.1f}%")

if __name__ == '__main__':
    main()
