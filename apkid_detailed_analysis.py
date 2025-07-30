#!/usr/bin/env python3
"""
APKiD-integrated detailed analysis for massive_name_obfuscation rule.
Shows percentage of conditions met with APKiD's rule system.
"""

import sys
import os
from pathlib import Path

# Add APKiD to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from apkid.main import Scanner
from apkid.rules import RulesManager

def analyze_apk_with_detailed_massive_obf(apk_path):
    """
    Analyze APK with detailed massive obfuscation condition breakdown.
    """
    print(f"🔍 Analyzing APK: {apk_path}")
    print(f"{'='*80}")
    
    try:
        # Initialize APKiD scanner
        rules_manager = RulesManager()
        scanner = Scanner(rules_manager)
        
        # Scan the APK
        results = scanner.scan_file(apk_path)
        
        print(f"✅ APKiD scan completed successfully")
        print(f"📊 Results summary:")
        
        # Check if massive obfuscation was detected
        massive_obf_detected = False
        for file_result in results:
            if 'dex' in file_result and file_result['dex']:
                for match in file_result['dex']:
                    if match['name'] == 'massive_name_obfuscation':
                        massive_obf_detected = True
                        print(f"   🔴 massive_name_obfuscation: DETECTED in {file_result['filename']}")
                        break
        
        if not massive_obf_detected:
            print(f"   🟢 massive_name_obfuscation: NOT DETECTED")
        
        # Show all detected obfuscation
        print(f"\n📋 All detected obfuscation methods:")
        obfuscation_count = 0
        for file_result in results:
            if 'dex' in file_result and file_result['dex']:
                for match in file_result['dex']:
                    print(f"   • {match['name']}")
                    obfuscation_count += 1
        
        if obfuscation_count == 0:
            print(f"   (No obfuscation detected)")
        
        # Now do detailed analysis on extracted DEX files
        print(f"\n{'='*80}")
        print(f"DETAILED MASSIVE OBFUSCATION ANALYSIS")
        print(f"{'='*80}")
        
        # Try to find DEX files in the APK
        import zipfile
        import tempfile
        
        dex_files_analyzed = 0
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                dex_files = [f for f in apk_zip.namelist() if f.endswith('.dex')]
                
                for dex_file in dex_files:
                    print(f"\n📁 Analyzing {dex_file}:")
                    print(f"{'='*50}")
                    
                    # Extract DEX to temporary file
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.dex') as temp_dex:
                        temp_dex.write(apk_zip.read(dex_file))
                        temp_dex_path = temp_dex.name
                    
                    try:
                        analyze_dex_detailed(temp_dex_path)
                        dex_files_analyzed += 1
                    finally:
                        os.unlink(temp_dex_path)
                        
        except Exception as e:
            print(f"⚠️  Could not extract DEX files for detailed analysis: {e}")
            print(f"   (APKiD results above are still valid)")
        
        if dex_files_analyzed == 0:
            print(f"⚠️  No DEX files could be analyzed in detail")
            print(f"   But APKiD scan results above show the overall detection status")
            
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        return

def analyze_dex_detailed(dex_file_path):
    """
    Detailed analysis of a single DEX file for massive obfuscation patterns.
    """
    try:
        with open(dex_file_path, 'rb') as f:
            dex_data = f.read()
    except Exception as e:
        print(f"❌ Error reading DEX file: {e}")
        return
    
    print(f"📊 DEX size: {len(dex_data):,} bytes")
    
    # Count pattern occurrences with more accurate methods
    import re
    
    # Basic pattern counts
    short_strings = (
        dex_data.count(b'\x00\x03a\x00') + 
        dex_data.count(b'\x00\x03b\x00') + 
        dex_data.count(b'\x00\x03c\x00') + 
        dex_data.count(b'\x00\x03d\x00') + 
        dex_data.count(b'\x00\x03e\x00')
    )
    
    single_classes = (
        dex_data.count(b'La;\x00') +
        dex_data.count(b'Lb;\x00') +
        dex_data.count(b'Lc;\x00')
    )
    
    # More accurate class counting
    class_pattern_matches = re.findall(rb'L[^;]*;', dex_data)
    total_classes = len(class_pattern_matches)
    
    # SDK package counts
    sdk_counts = {
        'google': dex_data.count(b'Lcom/google/'),
        'android': dex_data.count(b'Landroid/'),
        'androidx': dex_data.count(b'Landroidx/'),
        'kotlin': dex_data.count(b'Lkotlin/'),
        'java': dex_data.count(b'Ljava/'),
        'kotlinx': dex_data.count(b'Lkotlinx/'),
        'dalvik': dex_data.count(b'Ldalvik/'),
        'org': dex_data.count(b'Lorg/'),
    }
    
    # Legitimate short patterns (simplified)
    legitimate_patterns = [
        b'Lio/', b'Los/', b'Lui/', b'Lvm/', b'Ldb/', b'Ljs/',
        b'Lapp/', b'Lnet/', b'Lxml/', b'Lapi/', b'Lgui/'
    ]
    legitimate_short = sum(dex_data.count(p) for p in legitimate_patterns)
    
    sdk_classes = sum(sdk_counts.values()) + legitimate_short
    logical_classes = max(0, total_classes - sdk_classes)
    
    # Two and three char patterns
    two_char_matches = re.findall(rb'L[a-z]{2}/[a-z]{2};', dex_data)
    three_char_matches = re.findall(rb'L[a-z]{3}/[a-z]{3};', dex_data)
    two_char_classes = len(two_char_matches)
    three_char_classes = len(three_char_matches)
    
    # Single method patterns
    single_method_patterns = [b'\x00\x01' + bytes([c]) + b'\x00' for c in range(ord('a'), ord('z')+1)]
    single_methods = sum(dex_data.count(p) for p in single_method_patterns)
    
    print(f"\n📈 Pattern Analysis:")
    print(f"   Total classes: {total_classes:,}")
    print(f"   SDK classes: {sdk_classes:,}")
    print(f"   Logical classes: {logical_classes:,}")
    print(f"   Short strings (a-e): {short_strings:,}")
    print(f"   Single class names: {single_classes:,}")
    print(f"   Two-char classes: {two_char_classes:,}")
    print(f"   Three-char classes: {three_char_classes:,}")
    print(f"   Single methods: {single_methods:,}")
    
    # Evaluate conditions
    print(f"\n🎯 Condition Evaluation:")
    
    conditions_met = 0
    total_conditions = 7
    
    # Basic requirements
    min_classes_ok = total_classes >= 50
    logical_classes_ok = logical_classes > 0
    
    if min_classes_ok:
        conditions_met += 1
    if logical_classes_ok:
        conditions_met += 1
    
    print(f"   Basic reqs: {total_classes} >= 50 = {'✅' if min_classes_ok else '❌'}")
    print(f"   Logical classes: {logical_classes} > 0 = {'✅' if logical_classes_ok else '❌'}")
    
    if logical_classes == 0:
        print(f"   ⚠️  No logical classes found - cannot evaluate ratios")
        percentage = (conditions_met / total_conditions) * 100
        print(f"\n🎯 COMPLETION: {percentage:.1f}% ({conditions_met}/{total_conditions})")
        return
    
    # Method evaluations
    methods = [
        ("Method 1 - Short strings", short_strings > 20 and short_strings * 3 > logical_classes),
        ("Method 2 - Single classes", single_classes > 10 and single_classes * 2 > logical_classes),
        ("Method 3 - Two-char classes", (two_char_classes - legitimate_short) > 15 and (two_char_classes - legitimate_short) * 2 > logical_classes),
        ("Method 3b - Three-char classes", (three_char_classes - legitimate_short) > 15 and (three_char_classes - legitimate_short) * 3 > logical_classes),
        ("Method 4 - Single methods", single_methods > 30 and single_methods * 4 > logical_classes),
    ]
    
    for method_name, passed in methods:
        if passed:
            conditions_met += 1
        print(f"   {method_name}: {'✅' if passed else '❌'}")
    
    # Method 5 (alternative)
    combined_obf = short_strings + single_classes + (two_char_classes - legitimate_short) + (three_char_classes - legitimate_short)
    method5_passed = logical_classes > 50 and combined_obf * 5 > logical_classes * 3
    
    print(f"   Method 5 - Combined: {'✅' if method5_passed else '❌'} (alternative)")
    
    # Overall assessment
    any_method_passed = any(passed for _, passed in methods) or method5_passed
    rule_should_trigger = min_classes_ok and logical_classes_ok and any_method_passed
    
    percentage = (conditions_met / total_conditions) * 100
    
    print(f"\n📊 FINAL ASSESSMENT:")
    print(f"   Conditions met: {conditions_met}/{total_conditions}")
    print(f"   Completion percentage: {percentage:.1f}%")
    print(f"   Rule should trigger: {'✅ YES' if rule_should_trigger else '❌ NO'}")
    
    if rule_should_trigger:
        print(f"   🔴 This DEX shows signs of massive name obfuscation")
    else:
        print(f"   🟢 This DEX does not show massive name obfuscation")

def main():
    if len(sys.argv) != 2:
        print("Usage: python apkid_detailed_analysis.py <apk_file_path>")
        print("Example: python apkid_detailed_analysis.py app.apk")
        sys.exit(1)
    
    apk_path = sys.argv[1]
    if not os.path.exists(apk_path):
        print(f"❌ Error: File not found: {apk_path}")
        sys.exit(1)
    
    analyze_apk_with_detailed_massive_obf(apk_path)

if __name__ == "__main__":
    main()
