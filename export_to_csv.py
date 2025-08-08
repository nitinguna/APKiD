#!/usr/bin/env python3
"""
Export APK analysis results to CSV with specified columns
"""

import json
import csv
import os
from typing import Dict, Any, List

def extract_csv_columns(apk_result: Dict[str, Any]) -> Dict[str, str]:
    """
    Extract the 17 specified columns from an APK analysis result
    
    Returns a dictionary with the CSV column values
    """
    apk_name = apk_result.get('apk_name', 'Unknown')
    
    # Get the comprehensive final summary
    final_summary = apk_result.get('comprehensive_final_summary', {})
    
    # 1. manual_investigation_summary -> rules_passed
    manual_investigation = final_summary.get('manual_investigation_summary', {})
    rules_passed = manual_investigation.get('rules_passed', [])
    rules_passed_str = '; '.join(rules_passed) if rules_passed else 'None'
    
    # 2. margin_status -> status
    margin_status = manual_investigation.get('margin_status', {})
    status = margin_status.get('status', 'Unknown')
    
    # apkid_analysis_summary section
    apkid_summary = final_summary.get('apkid_analysis_summary', {})
    
    # 3. manipulator_detected
    manipulator_detected = str(apkid_summary.get('manipulator_detected', False))
    
    # 4. obfuscator_assessment
    obfuscator_assessment = apkid_summary.get('obfuscator_assessment', 'Unknown')
    
    # 5. compiler
    compiler = apkid_summary.get('compiler', 'Unknown')
    
    # r8_marker_analysis section
    r8_marker = final_summary.get('r8_marker_analysis', {})
    
    # 6. marker_found
    marker_found = str(r8_marker.get('marker_found', False))
    
    # 7. marker_status
    marker_status = r8_marker.get('marker_status', 'Unknown')
    
    # compilation_details section
    compilation_details = r8_marker.get('compilation_details', {})
    
    # 8. compilation_mode
    compilation_mode = compilation_details.get('compilation_mode', 'Unknown')
    
    # 9. r8_mode
    r8_mode = compilation_details.get('r8_mode', 'Unknown')
    
    # 10. marker_type
    marker_type = compilation_details.get('marker_type', 'Unknown')
    
    # NEW FIELDS - parameter_evaluations
    parameter_evaluations = margin_status.get('parameter_evaluations', [])
    
    # 11. threshold - append parameter names with thresholds
    thresholds = []
    actual_values = []
    for param_eval in parameter_evaluations:
        param_name = param_eval.get('parameter', 'unknown')
        threshold_val = param_eval.get('threshold', 'N/A')
        actual_val = param_eval.get('actual_value', 'N/A')
        thresholds.append(f"{param_name}: {threshold_val}")
        actual_values.append(f"{param_name}: {actual_val}")
    
    # 11. threshold
    threshold = '; '.join(thresholds) if thresholds else 'None'
    
    # 12. actual_value
    actual_value = '; '.join(actual_values) if actual_values else 'None'
    
    # Get comprehensive massive obfuscation result for final_dual_analysis
    comprehensive_result = apk_result.get('comprehensive_massive_obf_result', {})
    parsed_analysis = comprehensive_result.get('parsed_analysis', {})
    final_dual_analysis = parsed_analysis.get('final_dual_analysis', {})
    manual_inspection = final_dual_analysis.get('aggregated_analysis', {}).get('manual_inspection', {})
    
    # 13. total_classes
    total_classes = manual_inspection.get('total_classes', 0)
    
    # 14. logical_classes
    logical_classes = manual_inspection.get('logical_classes', 0)
    
    # 15. non_discovered_sdk_classes
    non_discovered_sdk_classes = manual_inspection.get('non_discovered_sdk_classes', 0)
    
    # 16. zebra_symbol_classes
    zebra_symbol_classes = manual_inspection.get('zebra_symbol_classes', 0)
    
    # 17. obfuscated_classes_sum (single_classes + two_digit_classes + three_char_classes)
    single_classes = manual_inspection.get('single_classes', 0)
    two_digit_classes = manual_inspection.get('two_digit_classes', 0)
    three_char_classes = manual_inspection.get('three_char_classes', 0)
    obfuscated_classes_sum = single_classes + two_digit_classes + three_char_classes
    
    return {
        'apk_name': apk_name,
        'rules_passed': rules_passed_str,
        'status': status,
        'manipulator_detected': manipulator_detected,
        'obfuscator_assessment': obfuscator_assessment,
        'compiler': compiler,
        'marker_found': marker_found,
        'marker_status': marker_status,
        'compilation_mode': compilation_mode,
        'r8_mode': r8_mode,
        'marker_type': marker_type,
        'threshold': threshold,
        'actual_value': actual_value,
        'total_classes': str(total_classes),
        'logical_classes': str(logical_classes),
        'non_discovered_sdk_classes': str(non_discovered_sdk_classes),
        'zebra_symbol_classes': str(zebra_symbol_classes),
        'obfuscated_classes_sum': str(obfuscated_classes_sum)
    }

def export_results_to_csv(input_json_path: str, output_csv_path: str) -> None:
    """
    Export APK analysis results from JSON to CSV format
    """
    print(f"📊 Exporting APK Analysis Results to CSV")
    print("=" * 60)
    
    # Check if input file exists
    if not os.path.exists(input_json_path):
        print(f"❌ Input file not found: {input_json_path}")
        return
    
    try:
        # Load the JSON data
        print(f"📂 Loading data from: {input_json_path}")
        with open(input_json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Get the results array
        results = data.get('results', [])
        if not results:
            print(f"❌ No results found in the JSON file")
            return
        
        print(f"📋 Found {len(results)} APK analysis results")
        
        # Define CSV column headers
        csv_headers = [
            'apk_name',
            'rules_passed',
            'status', 
            'manipulator_detected',
            'obfuscator_assessment',
            'compiler',
            'marker_found',
            'marker_status',
            'compilation_mode',
            'r8_mode',
            'marker_type',
            'threshold',
            'actual_value',
            'total_classes',
            'logical_classes',
            'non_discovered_sdk_classes',
            'zebra_symbol_classes',
            'obfuscated_classes_sum'
        ]
        
        # Extract data for each APK
        csv_rows = []
        processed_count = 0
        error_count = 0
        
        for result in results:
            try:
                csv_row = extract_csv_columns(result)
                csv_rows.append(csv_row)
                processed_count += 1
            except Exception as e:
                error_count += 1
                apk_name = result.get('apk_name', 'Unknown')
                print(f"⚠️  Error processing {apk_name}: {e}")
        
        # Write to CSV file
        print(f"💾 Writing CSV to: {output_csv_path}")
        with open(output_csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_headers)
            writer.writeheader()
            writer.writerows(csv_rows)
        
        # Summary
        print(f"✅ Export completed successfully!")
        print(f"   📊 Total APKs processed: {processed_count}")
        print(f"   ⚠️  Errors encountered: {error_count}")
        print(f"   📁 Output file: {output_csv_path}")
        
        # Show first few rows as preview
        if csv_rows:
            print(f"\n📋 Preview (first 3 rows):")
            print("-" * 120)
            for i, row in enumerate(csv_rows[:3]):
                print(f"Row {i+1}: {row['apk_name']}")
                print(f"  Status: {row['status']}")
                print(f"  Compiler: {row['compiler']}")
                print(f"  Obfuscator Assessment: {row['obfuscator_assessment']}")
                print(f"  Total Classes: {row['total_classes']}")
                print(f"  Logical Classes: {row['logical_classes']}")
                print(f"  Obfuscated Classes Sum: {row['obfuscated_classes_sum']}")
                print()
        
    except Exception as e:
        print(f"❌ Error processing file: {e}")
        import traceback
        traceback.print_exc()

def main():
    """
    Main function to export results to CSV
    """
    # File paths
    input_json = "quick_analysis_results.json"
    output_csv = "apk_analysis_results.csv"
    
    # Check if JSON file exists
    if not os.path.exists(input_json):
        print(f"❌ Input file not found: {input_json}")
        print("Please ensure quick_analysis_results.json exists in the current directory")
        return
    
    # Export to CSV
    export_results_to_csv(input_json, output_csv)

if __name__ == "__main__":
    main()
