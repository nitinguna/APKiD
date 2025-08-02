#!/usr/bin/env python3
"""
CSV Report Generator v2 - Enhanced for detailed dual analysis metrics
Processes APK analysis data and generates comprehensive CSV reports with YARA-STRICT and MANUAL INSPECTION metrics
"""

import json
import csv
import re
import os
from pathlib import Path

# Enhanced CSV header with detailed metrics
CSV_HEADER = [
    'APK Name',
    'Category', 
    'Number of DEX',
    'Size of APK (bytes)',
    'D8/R8 Marker',
    'R8 Mode',
    'Resource Confusion Set',
    'Compiler',
    'Obfuscator',
    'APKiD Result for Each DEX',
    'YARA Strict Results for Each DEX',
    'Manual Inspection Results for Each DEX'
]

def categorize_app(apk_name):
    """Categorize the app based on APK name"""
    apk_name_lower = apk_name.lower()
    if 'google' in apk_name_lower:
        return 'Google App'
    elif 'qualcomm' in apk_name_lower:
        return 'Qualcomm App'
    elif 'zebra' in apk_name_lower:
        return 'Zebra App'
    else:
        return 'Other App'

def parse_apkid_result(apkid_result):
    """Parse APKiD result to extract compiler and obfuscator information per DEX file"""
    if not apkid_result.get('success'):
        return "Parse Error", "Parse Error", "Parse Error", 0
    
    try:
        # Use the parsed_output if available, otherwise parse stdout
        if 'parsed_output' in apkid_result:
            data = apkid_result['parsed_output']
        else:
            output = apkid_result.get('stdout', '')
            if output.strip().startswith('{'):
                data = json.loads(output)
            else:
                return "Parse Error", "Parse Error", "Parse Error", 0
            
        # Extract DEX information per file
        dex_files = []
        dex_compilers = []
        dex_obfuscators = []
        
        for file_info in data.get('files', []):
            filename = file_info.get('filename', '')
            
            # Check if this is a DEX file
            if '.dex' in filename:
                # Extract DEX name from filename (e.g., "classes.dex" from "...!classes.dex")
                dex_name = filename.split('!')[-1] if '!' in filename else filename.split('/')[-1]
                dex_files.append(dex_name)
                
                # Collect compilers and obfuscators for this specific DEX
                file_compilers = []
                file_obfuscators = []
                
                matches = file_info.get('matches', {})
                for category, detections in matches.items():
                    for detection in detections:
                        detection_lower = detection.lower()
                        
                        # Categorize compiler vs obfuscator
                        if category == 'compiler' or any(keyword in detection_lower for keyword in ['compiler', 'd8', 'r8', 'dx']):
                            file_compilers.append(detection)
                        elif category == 'obfuscator' or any(keyword in detection_lower for keyword in ['obfuscat', 'protect', 'guard', 'crypt', 'method']):
                            file_obfuscators.append(detection)
                
                # Format per-DEX results
                if file_compilers:
                    compiler_line = f"{dex_name}: {', '.join(file_compilers)}"
                else:
                    compiler_line = f"{dex_name}: None detected"
                dex_compilers.append(compiler_line)
                
                if file_obfuscators:
                    obfuscator_line = f"{dex_name}: {', '.join(file_obfuscators)}"
                else:
                    obfuscator_line = f"{dex_name}: None detected"
                dex_obfuscators.append(obfuscator_line)
        
        num_dex = len(dex_files)
        
        # Join with newlines for proper CSV formatting
        compiler_str = '\n'.join(dex_compilers) if dex_compilers else 'No DEX files found'
        obfuscator_str = '\n'.join(dex_obfuscators) if dex_obfuscators else 'No DEX files found'
        
        # Return the full output as well for the APKiD column
        if 'parsed_output' in apkid_result:
            full_output = json.dumps(data, separators=(',', ':'))
        else:
            full_output = apkid_result.get('stdout', '')
            
        return full_output, compiler_str, obfuscator_str, num_dex
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        return f"Parse Error: {str(e)}", "Parse Error", "Parse Error", 0

def extract_comprehensive_results(comp_result):
    """Extract YARA strict and manual analysis results with detailed metrics"""
    if not comp_result.get('success'):
        return "N/A", "N/A"
    
    stdout = comp_result.get('stdout', '')
    
    # Extract YARA strict and manual inspection results
    yara_results = []
    manual_results = []
    
    # Find all detailed analysis sections for each DEX file
    dex_sections = re.findall(r'📊 DETAILED ANALYSIS: (.*?\.dex)(.*?)(?=📊 DETAILED ANALYSIS:|📋 FINAL SUMMARY)', stdout, re.DOTALL)
    
    for dex_name, section_content in dex_sections:
        # Process YARA-STRICT Analysis section
        yara_section = re.search(r'📊 YARA-STRICT Analysis \(DEX string table format\):(.*?)📋 MANUAL INSPECTION Analysis', section_content, re.DOTALL)
        if yara_section:
            yara_text = yara_section.group(1)
            yara_info = []
            
            # Extract all detailed metrics from YARA section
            metrics = {
                'total_classes': r'Total classes \(L\.\.\.\;\): ([\d,]+)',
                'logical_classes': r'Logical classes: ([\d,]+)',
                'short_strings': r'Short strings \(a-e\): ([\d,]+)',
                'single_classes': r'Single class names: ([\d,]+)',
                'two_digit_classes': r'Two-char classes: ([\d,]+)',
                'three_char_classes': r'Three-char classes: ([\d,]+)',
                'single_methods': r'Single methods: ([\d,]+)'
            }
            
            for metric_name, pattern in metrics.items():
                match = re.search(pattern, yara_text)
                if match:
                    value = match.group(1).replace(',', '')
                    yara_info.append(f"{metric_name}:{value}")
            
            # Extract YARA-STRICT Results from Final Assessment (this comes AFTER all sections)
            final_assessment = re.search(r'📊 Final Assessment:(.*?)$', section_content, re.DOTALL)
            if final_assessment:
                assessment_text = final_assessment.group(1)
                
                yara_results_section = re.search(r'📊 YARA-STRICT Results \(Primary\):(.*?)📋 MANUAL INSPECTION Results', assessment_text, re.DOTALL)
                if yara_results_section:
                    yara_final_text = yara_results_section.group(1)
                    
                    methods_passed = re.search(r'Methods passed: (\d+/\d+)', yara_final_text)
                    if methods_passed:
                        yara_info.append(f"methods_passed:{methods_passed.group(1)}")
                    
                    completion_pct = re.search(r'Completion percentage: ([\d.]+)%', yara_final_text)
                    if completion_pct:
                        yara_info.append(f"completion:{completion_pct.group(1)}%")
                    
                    rule_trigger = re.search(r'Rule should trigger: [🟢🔴] (\w+)', yara_final_text)
                    if rule_trigger:
                        yara_info.append(f"trigger:{rule_trigger.group(1)}")
            
            yara_result = f"{dex_name}: {','.join(yara_info)}" if yara_info else f"{dex_name}: No data"
            yara_results.append(yara_result)
        
        # Process MANUAL INSPECTION Analysis section
        manual_section = re.search(r'📋 MANUAL INSPECTION Analysis \(broader patterns\):(.*?)🔍 COMPARISON', section_content, re.DOTALL)
        if manual_section:
            manual_text = manual_section.group(1)
            manual_info = []
            
            # Extract all detailed metrics for manual inspection
            manual_metrics = {
                'total_classes': r'Total unique classes: ([\d,]+)',
                'logical_classes': r'Logical classes analyzed: ([\d,]+)',
                'short_strings': r'Short strings \(a-e\): ([\d,]+)',
                'single_classes': r'Single-digit classes: ([\d,]+)',
                'two_digit_classes': r'Two-digit classes: ([\d,]+)',
                'three_char_classes': r'Three-digit classes: ([\d,]+)',
                'single_methods': r'Single-char methods: ([\d,]+)'
            }
            
            for metric_name, pattern in manual_metrics.items():
                match = re.search(pattern, manual_text)
                if match:
                    value = match.group(1).replace(',', '')
                    manual_info.append(f"{metric_name}:{value}")
            
            # Extract MANUAL INSPECTION Results from Final Assessment
            final_assessment = re.search(r'📊 Final Assessment:(.*?)$', section_content, re.DOTALL)
            if final_assessment:
                assessment_text = final_assessment.group(1)
                
                manual_results_section = re.search(r'📋 MANUAL INSPECTION Results \(Comparison\):(.*?)🔍 Effectiveness Gap', assessment_text, re.DOTALL)
                if manual_results_section:
                    manual_final_text = manual_results_section.group(1)
                    
                    methods_passed = re.search(r'Methods passed: (\d+/\d+)', manual_final_text)
                    if methods_passed:
                        manual_info.append(f"methods_passed:{methods_passed.group(1)}")
                    
                    rule_trigger = re.search(r'Rule would trigger: [🟢🔴] (\w+)', manual_final_text)
                    if rule_trigger:
                        manual_info.append(f"trigger:{rule_trigger.group(1)}")
            
            manual_result = f"{dex_name}: {','.join(manual_info)}" if manual_info else f"{dex_name}: No data"
            manual_results.append(manual_result)
    
    yara_str = '\n'.join(yara_results) if yara_results else "N/A"
    manual_str = '\n'.join(manual_results) if manual_results else "N/A"
    
    return yara_str, manual_str

def process_quick_analysis_data():
    """Process the quick analysis results and generate CSV"""
    
    # Load the JSON data
    json_file = 'quick_analysis_results.json'
    if not os.path.exists(json_file):
        print(f"❌ Error: {json_file} not found. Please run quick_apk_analyzer.py first.")
        return
    
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Get the results array from the JSON structure
    results = data.get('results', [])
    print(f"📊 Processing {len(results)} APK files...")
    
    # Prepare CSV data
    csv_data = []
    category_counts = {}
    
    for analysis_data in results:
        # Extract basic information
        apk_name = analysis_data.get('apk_name', 'Unknown')
        category = categorize_app(apk_name)
        
        # Count categories
        category_counts[category] = category_counts.get(category, 0) + 1
        
        # Get APK size in bytes (convert from MB)
        apk_size_mb = analysis_data.get('apk_size_mb', 0)
        apk_size_bytes = int(apk_size_mb * 1024 * 1024) if apk_size_mb else 0
        
        # Parse APKiD results
        apkid_result = analysis_data.get('apkid_result', {})
        apkid_output, compiler, obfuscator, num_dex_apkid = parse_apkid_result(apkid_result)
        
        # Get actual number of DEX files from comprehensive analysis
        comp_result = analysis_data.get('comprehensive_massive_obf_result', {})
        if comp_result.get('success') and 'parsed_analysis' in comp_result:
            num_dex = comp_result['parsed_analysis'].get('dex_files_analyzed', num_dex_apkid)
        else:
            num_dex = num_dex_apkid
        
        # Extract R8 marker information
        r8_result = analysis_data.get('r8_extract_marker_result', {})
        d8_r8_marker = "Not detected"
        r8_mode = "Not detected"
        
        if r8_result.get('success') and 'parsed_marker' in r8_result:
            marker_info = r8_result['parsed_marker']
            marker_type = marker_info.get('marker_type', '')
            if marker_type:
                d8_r8_marker = "Present"
                # Get R8 mode if it's an R8 marker
                if marker_type == 'R8':
                    r8_mode = marker_info.get('r8-mode', 'Not specified')
                    compilation_mode = marker_info.get('compilation-mode', '')
                    if compilation_mode:
                        r8_mode = f"{r8_mode}/{compilation_mode}"
        
        # Resource confusion detection (check APKiD output)
        resource_confusion = "Not detected"
        if 'resource' in apkid_output.lower() or 'confusion' in apkid_output.lower():
            resource_confusion = "Detected"
        
        # Extract comprehensive analysis results with detailed metrics
        yara_strict_results, manual_inspection_results = extract_comprehensive_results(comp_result)
        
        # Create CSV row
        row = [
            apk_name,
            category,
            num_dex,
            apk_size_bytes,
            d8_r8_marker,
            r8_mode,
            resource_confusion,
            compiler,
            obfuscator,
            apkid_output.replace('\n', ' ').replace('\r', ' '),  # Clean APKiD output
            yara_strict_results,
            manual_inspection_results
        ]
        
        csv_data.append(row)
    
    # Write CSV file with proper newline handling
    output_file = 'detailed_analysis_report_v4.csv'
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
        writer.writerow(CSV_HEADER)
        writer.writerows(csv_data)
    
    print(f"✅ Generated detailed analysis report: {output_file}")
    print(f"📋 Category Distribution:")
    for category, count in category_counts.items():
        print(f"   {category}: {count} apps")

if __name__ == "__main__":
    process_quick_analysis_data()
