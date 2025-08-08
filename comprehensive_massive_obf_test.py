#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comprehensive massive obfuscation rule testing with percentage breakdown.
Works with compiled APKiD rules and shows detailed condition analysis.
"""

import sys
import os
import tempfile
import zipfile
import subprocess
import json
import argparse
import re
import struct
import importlib.util
import traceback
from pathlib import Path
import codecs

# Set up proper encoding for Windows
if sys.platform == "win32":
    # Configure stdout to handle unicode properly
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    else:
        # For older Python versions, wrap stdout
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach(), errors='replace')
    
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    else:
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.detach(), errors='replace')

# Add APKiD to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def safe_print(*args, **kwargs):
    """Safe print function that handles unicode encoding issues."""
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        # If unicode fails, convert all args to ASCII with replacement
        safe_args = []
        for arg in args:
            if isinstance(arg, str):
                safe_args.append(arg.encode('ascii', errors='replace').decode('ascii'))
            else:
                safe_args.append(str(arg).encode('ascii', errors='replace').decode('ascii'))
        print(*safe_args, **kwargs)

def load_sdk_config_from_file(config_path):
    """Load SDK configuration from temporary JSON file"""
    if not config_path or not os.path.exists(config_path):
        return None
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        return config
    except Exception as e:
        safe_print(f"Warning: Failed to load SDK config: {e}")
        return None

def test_massive_obfuscation_with_percentage(input_file, sdk_config=None):
    """
    Test massive obfuscation rule and show percentage of conditions met.
    Works with APK or DEX files.
    
    Args:
        input_file: Path to APK or DEX file
        sdk_config: Optional SDK configuration dict with custom patterns
    """
    
    safe_print(f"🔍 Testing massive obfuscation rule on: {input_file}")
    if sdk_config:
        safe_print(f"📦 Using custom SDK configuration for package: {sdk_config.get('package_name', 'unknown')}")
    safe_print(f"{'='*80}")
    
    # First, try APKiD scan using command-line interface (same as quick_apk_analyzer)
    try:
        import subprocess
        import json
        
        # Run APKiD using the module approach to avoid relative import issues
        apkid_command = [sys.executable, '-m', 'apkid', '--json', input_file]
        
        result = subprocess.run(
            apkid_command,
            capture_output=True,
            text=True,
            timeout=30,
            encoding='utf-8',
            errors='ignore'
        )
        
        if result.returncode == 0 and result.stdout:
            # Parse JSON output
            apkid_data = json.loads(result.stdout)
            safe_print(f"✅ APKiD scan completed")
            
            # Check if massive obfuscation was detected
            massive_obf_detected = False
            all_obfuscation = []
            
            for file_info in apkid_data.get('files', []):
                matches = file_info.get('matches', {})
                obfuscators = matches.get('obfuscator', [])
                all_obfuscation.extend(obfuscators)
                
                # Check for massive name obfuscation
                for obf in obfuscators:
                    if 'massive name obfuscation' in obf:
                        massive_obf_detected = True
            
            safe_print(f"🎯 APKiD Results:")
            safe_print(f"   massive_name_obfuscation: {'🔴 DETECTED' if massive_obf_detected else '🟢 NOT DETECTED'}")
            
            if all_obfuscation:
                unique_obfuscation = list(set(all_obfuscation))
                # Remove massive name obfuscation from the list for "other" obfuscation
                other_obf = [o for o in unique_obfuscation if 'massive name obfuscation' not in o]
                safe_print(f"   Other obfuscation detected: {', '.join(other_obf) if other_obf else 'None'}")
        else:
            raise Exception(f"APKiD command failed with return code {result.returncode}: {result.stderr}")
            
    except Exception as e:
        safe_print(f"⚠️  APKiD scan failed: {e}")
        safe_print(f"   Continuing with manual analysis...")
        massive_obf_detected = None
    
    # Extract DEX files for detailed analysis
    dex_files = []
    
    if input_file.lower().endswith('.apk'):
        safe_print(f"\n📦 Extracting DEX files from APK...")
        try:
            with zipfile.ZipFile(input_file, 'r') as apk_zip:
                dex_names = [f for f in apk_zip.namelist() if f.endswith('.dex')]
                
                for dex_name in dex_names:
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.dex') as temp_dex:
                        temp_dex.write(apk_zip.read(dex_name))
                        dex_files.append((dex_name, temp_dex.name))
                        
                safe_print(f"   Extracted {len(dex_files)} DEX files: {', '.join([name for name, _ in dex_files])}")
                        
        except Exception as e:
            safe_print(f"❌ Error extracting DEX files: {e}")
            return
            
    elif input_file.lower().endswith('.dex'):
        dex_files = [(os.path.basename(input_file), input_file)]
        safe_print(f"📁 Analyzing single DEX file")
    else:
        safe_print(f"❌ Unsupported file type. Please provide APK or DEX file.")
        return
    
    # Analyze each DEX file and combine results for multi-DEX evaluation
    overall_max_percentage = 0
    overall_should_trigger = False
    total_dex_count = len(dex_files)  # Calculate total DEX count for modality determination
    
    if total_dex_count > 1:
        # MULTI-DEX ANALYSIS: Combine pattern counts from all DEX files
        safe_print(f"\n{'='*80}")
        safe_print(f"🔄 MULTI-DEX COMBINED ANALYSIS ({total_dex_count} DEX files)")
        safe_print(f"{'='*80}")
        
        # Initialize combined pattern counts
        combined_yara_patterns = {}
        combined_manual_patterns = {}
        combined_total_classes = 0
        
        # Analyze each DEX file and collect pattern counts
        for dex_name, dex_path in dex_files:
            safe_print(f"\n📊 Extracting patterns from: {dex_name}")
            safe_print(f"{'─'*50}")
            
            try:
                # Get pattern counts from this DEX file (without rule evaluation)
                dex_patterns = extract_dex_patterns(dex_path, sdk_config)
                
                # Combine YARA patterns
                for key, value in dex_patterns['yara'].items():
                    combined_yara_patterns[key] = combined_yara_patterns.get(key, 0) + value
                
                # Combine manual patterns
                for key, value in dex_patterns['manual'].items():
                    combined_manual_patterns[key] = combined_manual_patterns.get(key, 0) + value
                
                # Add to total classes
                combined_total_classes += dex_patterns['total_classes']
                
                safe_print(f"   ✅ Patterns extracted from {dex_name}")
                
            except Exception as e:
                safe_print(f"   ❌ Error extracting patterns from {dex_name}: {e}")
                continue
        
        # Now evaluate multi-DEX rules against combined patterns
        safe_print(f"\n{'='*60}")
        safe_print(f"📊 COMBINED MULTI-DEX RULE EVALUATION")
        safe_print(f"{'='*60}")
        safe_print(f"📋 Total DEX files: {total_dex_count}")
        safe_print(f"📋 Combined total classes: {combined_total_classes:,}")
        
        try:
            # Evaluate combined patterns against multi-DEX rules
            percentage, should_trigger, methods_detail, methods_summary = evaluate_combined_multidex_patterns(
                combined_yara_patterns, combined_manual_patterns, combined_total_classes, total_dex_count, sdk_config
            )
            
            overall_max_percentage = percentage
            overall_should_trigger = should_trigger
            
        except Exception as e:
            safe_print(f"❌ Error in combined multi-DEX analysis: {e}")
            # Fallback to individual analysis
            safe_print(f"🔄 Falling back to individual DEX analysis...")
            
    else:
        # SINGLE DEX ANALYSIS: Use existing individual analysis
        safe_print(f"\n{'='*60}")
        safe_print(f"📊 SINGLE DEX ANALYSIS")
        safe_print(f"{'='*60}")
    
    # Individual DEX analysis (for single DEX or fallback)
    if total_dex_count == 1 or overall_max_percentage == 0:
        for dex_name, dex_path in dex_files:
            safe_print(f"\n{'='*60}")
            safe_print(f"📊 DETAILED ANALYSIS: {dex_name}")
            safe_print(f"{'='*60}")
            
            try:
                result = analyze_single_dex_detailed(dex_path, sdk_config, total_dex_count)
                
                # Handle both old and new return formats for backward compatibility
                if len(result) == 4:
                    percentage, should_trigger, methods_detail, methods_summary = result
                else:
                    percentage, should_trigger = result
                    methods_detail, methods_summary = None, None
                    
                overall_max_percentage = max(overall_max_percentage, percentage)
                overall_should_trigger = overall_should_trigger or should_trigger
                
            except Exception as e:
                safe_print(f"❌ Error analyzing {dex_name}: {e}")
            
            # Clean up temporary files
            if input_file.lower().endswith('.apk'):
                try:
                    os.unlink(dex_path)
                except:
                    pass
    
    # Final summary
    safe_print(f"\n{'='*80}")
    safe_print(f"📋 FINAL SUMMARY")
    safe_print(f"{'='*80}")
    
    safe_print(f"Files analyzed: {len(dex_files)} DEX files")
    safe_print(f"Highest completion percentage: {overall_max_percentage:.1f}%")
    safe_print(f"Manual analysis result: {'🔴 SHOULD TRIGGER' if overall_should_trigger else '🟢 SHOULD NOT TRIGGER'}")
    
    if massive_obf_detected is not None:
        apkid_result = "🔴 DETECTED" if massive_obf_detected else "🟢 NOT DETECTED"
        safe_print(f"APKiD scan result: {apkid_result}")
        
        if overall_should_trigger == massive_obf_detected:
            safe_print(f"Consistency: ✅ Manual analysis matches APKiD result")
        else:
            safe_print(f"Consistency: ⚠️  Manual analysis differs from APKiD result")
    
    return overall_max_percentage, overall_should_trigger

def extract_dex_patterns(dex_file_path, sdk_config=None):
    """
    Extract pattern counts from a single DEX file without rule evaluation.
    Returns pattern dictionaries for later combination.
    
    Args:
        dex_file_path: Path to DEX file
        sdk_config: Optional SDK configuration dict
    
    Returns:
        dict: Contains 'yara', 'manual', and 'total_classes' pattern counts
    """
    
    try:
        with open(dex_file_path, 'rb') as f:
            dex_data = f.read()
    except Exception as e:
        safe_print(f"❌ Error reading DEX file: {e}")
        return {'yara': {}, 'manual': {}, 'total_classes': 0}
    
    safe_print(f"📊 DEX file size: {len(dex_data):,} bytes")
    
    # Read DEX header to get class_defs_size (like YARA does)
    if len(dex_data) >= 0x70:  # Minimum DEX header size
        dex_header_class_defs_size = struct.unpack('<I', dex_data[0x60:0x64])[0]
        safe_print(f"📊 DEX header class_defs_size: {dex_header_class_defs_size:,}")
    else:
        safe_print(f"❌ DEX file too small for header analysis")
        return {'yara': {}, 'manual': {}, 'total_classes': 0}
    
    # Convert to latin-1 string for regex operations (preserves all byte values)
    try:
        data_str = dex_data.decode('latin-1')
    except:
        data_str = str(dex_data)
    
    # YARA PATTERNS - Same logic as analyze_single_dex_detailed but just extraction
    yara_patterns = {}
    
    # Short string patterns - EXACT YARA bytes
    yara_patterns['short_a'] = len(re.findall(r'\x00\x03a\x00', data_str))
    yara_patterns['short_b'] = len(re.findall(r'\x00\x03b\x00', data_str))  
    yara_patterns['short_c'] = len(re.findall(r'\x00\x03c\x00', data_str))
    yara_patterns['short_d'] = len(re.findall(r'\x00\x03d\x00', data_str))
    yara_patterns['short_e'] = len(re.findall(r'\x00\x03e\x00', data_str))
    
    # Single class patterns
    single_class_pattern = re.findall(r'L[a-z];\x00', data_str)
    yara_patterns['single_class_total'] = len(single_class_pattern)
    yara_patterns['single_class_comprehensive'] = yara_patterns['single_class_total']
    
    # Two and three character class patterns
    yara_patterns['two_char_class'] = len(re.findall(r'\x00.L..\/..;\x00', data_str, re.DOTALL))
    yara_patterns['three_char_class'] = len(re.findall(r'\x00.L...\/.../\;\x00', data_str, re.DOTALL))
    
    # Single method pattern
    yara_patterns['single_method'] = len(re.findall(r'\x00\x01[a-z]\x00', data_str))
    
    # Main class pattern
    yara_patterns['class_pattern'] = len(re.findall(r'\x00[\x02-\x7F]L+[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    
    # SDK exclusion patterns - same as analyze_single_dex_detailed
    yara_patterns['google_class'] = len(re.findall(r'\x00[\x02-\x7F]L+com/google/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['com_android_class'] = len(re.findall(r'\x00[\x02-\x7F]L+com/android/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['android_class'] = len(re.findall(r'\x00[\x02-\x7F]L+android/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['androidx_class'] = len(re.findall(r'\x00[\x02-\x7F]L+androidx/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['kotlin_class'] = len(re.findall(r'\x00[\x02-\x7F]L+kotlin/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['java_class'] = len(re.findall(r'\x00[\x02-\x7F]L+java/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['kotlinx_class'] = len(re.findall(r'\x00[\x02-\x7F]L+kotlinx/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['dalvik_class'] = len(re.findall(r'\x00[\x02-\x7F]L+dalvik/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['org_class'] = len(re.findall(r'\x00[\x02-\x7F]L+org/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['retrofit2_class'] = len(re.findall(r'\x00[\x02-\x7F]L+retrofit2/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['ro_class'] = len(re.findall(r'\x00[\x02-\x7F]L+ro/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['view_class'] = len(re.findall(r'\x00[\x02-\x7F]L+view/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['persist_class'] = len(re.findall(r'\x00[\x02-\x7F]L+persist/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['sun_class'] = len(re.findall(r'\x00[\x02-\x7F]L+sun/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['guava_class'] = len(re.findall(r'\x00[\x02-\x7F]L+guava/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['vnd_android_class'] = len(re.findall(r'\x00[\x02-\x7F]L+vnd/android/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['schemas_android_class'] = len(re.findall(r'\x00[\x02-\x7F]L+schemas/android/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['in_collections_class'] = len(re.findall(r'\x00[\x02-\x7F]L+in/collections/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['media_class'] = len(re.findall(r'\x00[\x02-\x7F]L+media/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['legitimate_short'] = len(re.findall(r'L(io|os|ui|vm|db|js|sx|tv|ai|ar|vr|3d|r|app|net|xml|api|gui|jwt|ssl|tls|rsa|aes|des|md5|sha|url|uri|css|dom|xml|sql|tcp|udp|ftp|ssh|git|svn|cvs|yml|pdf|jpg|png|gif|bmp|ico|zip|tar|rar|log|tmp|bin|lib|jar|war|ear|dex|oat|odex|vdex|art)/', data_str))
    
    # Custom SDK and legitimate patterns
    yara_patterns['custom_sdk_classes'] = 0
    yara_patterns['custom_legitimate'] = 0
    
    # MANUAL PATTERNS - Same logic as analyze_single_dex_detailed but just extraction
    manual_patterns = {}
    
    # Find ALL class patterns
    all_classes = re.findall(r'L+[a-zA-Z0-9\$_/]+;', data_str)
    unique_classes = list(set(all_classes))
    
    # Obfuscation pattern analysis
    obfuscation_single_classes = []
    obfuscation_double_classes = []
    obfuscation_triple_classes = []
    
    for class_name in unique_classes:
        clean_name = class_name[1:-1] if class_name.startswith('L') and class_name.endswith(';') else class_name
        
        if '/' in clean_name:
            parts = clean_name.split('/')
            single_char_parts = [part for part in parts if len(part) == 1 and part.isalpha()]
            if single_char_parts:
                obfuscation_single_classes.append(class_name)
            
            if (len(parts) == 2 and 
                len(parts[0]) == 2 and len(parts[1]) == 2 and
                parts[0].isalpha() and parts[1].isalpha()):
                obfuscation_double_classes.append(class_name)
            elif (len(parts) == 2 and 
                  len(parts[0]) == 3 and len(parts[1]) == 3 and
                  parts[0].isalpha() and parts[1].isalpha()):
                obfuscation_triple_classes.append(class_name)
        else:
            if len(clean_name) == 2 and clean_name.isalpha():
                obfuscation_double_classes.append(class_name)
            elif len(clean_name) == 3 and clean_name.isalpha():
                obfuscation_triple_classes.append(class_name)
            elif len(clean_name) == 1 and clean_name.isalpha():
                obfuscation_single_classes.append(class_name)
    
    # Store manual pattern counts
    manual_patterns['single_digit_classes'] = len(obfuscation_single_classes)
    manual_patterns['two_digit_classes'] = len(obfuscation_double_classes)
    manual_patterns['three_digit_classes'] = len(obfuscation_triple_classes)
    manual_patterns['total_classes'] = len(unique_classes)
    
    # Manual analysis for method names and short strings
    single_char_methods = re.findall(r'[^a-zA-Z][a-z]\x00', data_str)
    manual_single_methods = [m for m in single_char_methods if len(m.strip('\x00')) == 1]
    manual_patterns['single_methods'] = len(manual_single_methods)
    
    # Enhanced short string detection (simplified for extraction)
    manual_short_strings = []
    for char_code in [0x61, 0x62, 0x63, 0x64, 0x65]:  # a, b, c, d, e
        pattern = bytes([0x00, 0x03, char_code, 0x00])
        manual_short_strings.extend([m.start() for m in re.finditer(re.escape(pattern), data_str.encode('latin-1'))])
    manual_patterns['short_strings'] = len(set(manual_short_strings))
    
    safe_print(f"   📊 Extracted patterns: YARA={len(yara_patterns)} fields, Manual={len(manual_patterns)} fields")
    
    return {
        'yara': yara_patterns,
        'manual': manual_patterns,
        'total_classes': dex_header_class_defs_size
    }

def evaluate_combined_multidex_patterns(combined_yara_patterns, combined_manual_patterns, combined_total_classes, total_dex_count, sdk_config=None):
    """
    Evaluate multi-DEX rules against combined pattern counts from all DEX files.
    
    Args:
        combined_yara_patterns: Combined YARA pattern counts from all DEX files
        combined_manual_patterns: Combined manual pattern counts from all DEX files  
        combined_total_classes: Combined total class count from all DEX files
        total_dex_count: Number of DEX files in the APK
        sdk_config: Optional SDK configuration dict
    
    Returns:
        tuple: (percentage, should_trigger, methods_detail, methods_summary)
    """
    
    safe_print(f"📊 Combined Multi-DEX Pattern Analysis:")
    safe_print(f"   Total DEX files: {total_dex_count}")
    safe_print(f"   Combined total classes: {combined_total_classes:,}")
    
    # Calculate combined SDK classes (same logic as single DEX but with combined counts)
    sdk_classes_raw = (
        combined_yara_patterns.get('google_class', 0) + 
        combined_yara_patterns.get('com_android_class', 0) + 
        combined_yara_patterns.get('android_class', 0) + 
        combined_yara_patterns.get('androidx_class', 0) + 
        combined_yara_patterns.get('kotlin_class', 0) + 
        combined_yara_patterns.get('java_class', 0) + 
        combined_yara_patterns.get('kotlinx_class', 0) + 
        combined_yara_patterns.get('dalvik_class', 0) + 
        combined_yara_patterns.get('org_class', 0) + 
        combined_yara_patterns.get('retrofit2_class', 0) + 
        combined_yara_patterns.get('ro_class', 0) + 
        combined_yara_patterns.get('view_class', 0) + 
        combined_yara_patterns.get('persist_class', 0) + 
        combined_yara_patterns.get('sun_class', 0) + 
        combined_yara_patterns.get('guava_class', 0) + 
        combined_yara_patterns.get('vnd_android_class', 0) + 
        combined_yara_patterns.get('schemas_android_class', 0) + 
        combined_yara_patterns.get('in_collections_class', 0) + 
        combined_yara_patterns.get('media_class', 0) + 
        combined_yara_patterns.get('legitimate_short', 0) + 
        combined_yara_patterns.get('custom_legitimate', 0) + 
        combined_yara_patterns.get('custom_sdk_classes', 0)
    )
    
    # Cap SDK classes to never exceed total classes
    sdk_classes = min(sdk_classes_raw, combined_total_classes)
    yara_approximate_logical_classes = max(0, combined_total_classes - sdk_classes)
    
    # Combined pattern calculations
    short_strings = (
        combined_yara_patterns.get('short_a', 0) + 
        combined_yara_patterns.get('short_b', 0) + 
        combined_yara_patterns.get('short_c', 0) + 
        combined_yara_patterns.get('short_d', 0) + 
        combined_yara_patterns.get('short_e', 0)
    )
    single_classes = combined_yara_patterns.get('single_class_comprehensive', 0)
    two_char_classes = combined_yara_patterns.get('two_char_class', 0)
    three_char_classes = combined_yara_patterns.get('three_char_class', 0)
    single_methods = combined_yara_patterns.get('single_method', 0)
    
    safe_print(f"   📊 Combined YARA patterns:")
    safe_print(f"      Short strings (a-e): {short_strings:,}")
    safe_print(f"      Single classes: {single_classes:,}")
    safe_print(f"      Two-char classes: {two_char_classes:,}")
    safe_print(f"      Three-char classes: {three_char_classes:,}")
    safe_print(f"      Single methods: {single_methods:,}")
    safe_print(f"      SDK classes: {sdk_classes:,}")
    safe_print(f"      Logical classes: {yara_approximate_logical_classes:,}")
    
    safe_print(f"   📊 Combined Manual patterns:")
    safe_print(f"      Short strings: {combined_manual_patterns.get('short_strings', 0):,}")
    safe_print(f"      Single-digit classes: {combined_manual_patterns.get('single_digit_classes', 0):,}")
    safe_print(f"      Two-digit classes: {combined_manual_patterns.get('two_digit_classes', 0):,}")
    safe_print(f"      Three-digit classes: {combined_manual_patterns.get('three_digit_classes', 0):,}")
    safe_print(f"      Single methods: {combined_manual_patterns.get('single_methods', 0):,}")
    
    # Basic requirements check
    req1_min_classes = combined_total_classes >= 50
    req2_logical_classes_yara = yara_approximate_logical_classes > 0
    req2_logical_classes_manual = combined_manual_patterns.get('total_classes', 0) > 0
    
    safe_print(f"\n🎯 Combined Multi-DEX Requirements:")
    safe_print(f"   Min classes (50): {combined_total_classes} >= 50 = {'✅' if req1_min_classes else '❌'}")
    safe_print(f"   YARA logical classes > 0: {yara_approximate_logical_classes} = {'✅' if req2_logical_classes_yara else '❌'}")
    safe_print(f"   Manual logical classes > 0: {combined_manual_patterns.get('total_classes', 0)} = {'✅' if req2_logical_classes_manual else '❌'}")
    
    if not req1_min_classes:
        safe_print(f"❌ Multi-DEX analysis failed: Insufficient total classes")
        return 0, False, {}, {}
    
    # Load rules and determine modality
    try:
        rules_config = load_obfuscation_rules_config()
        
        # For multi-DEX, use manual logical classes for modality determination
        logical_classes_for_eval = combined_manual_patterns.get('total_classes', yara_approximate_logical_classes)
        modality, _ = determine_dex_modality(total_dex_count, yara_approximate_logical_classes, logical_classes_for_eval)
        
        safe_print(f"\n📊 COMBINED MULTI-DEX RULE EVALUATION:")
        safe_print(f"{'='*60}")
        safe_print(f"📋 DEX Modality: {modality}")
        safe_print(f"📋 Total DEX count: {total_dex_count}")
        safe_print(f"📋 Combined logical classes: {logical_classes_for_eval:,}")
        
        # Try both analysis methods for multi-DEX
        analysis_methods = ["manual_investigation", "yara_strict"]
        rule_types = ["optimal", "minimal"]
        
        evaluation_results = []
        best_result = None
        
        for analysis_method in analysis_methods:
            safe_print(f"\n🔍 Evaluating {analysis_method.upper()} multi-DEX rules:")
            safe_print(f"{'─'*50}")
            
            # Select pattern data based on analysis method
            if analysis_method == "yara_strict":
                pattern_data = {
                    'short_strings': short_strings,
                    'single_classes': single_classes,
                    'two_char_classes': two_char_classes,
                    'three_char_classes': three_char_classes,
                    'single_methods': single_methods,
                    'logical_classes': yara_approximate_logical_classes
                }
            else:  # manual_investigation
                pattern_data = {
                    'short_strings': combined_manual_patterns.get('short_strings', 0),
                    'single_classes': combined_manual_patterns.get('single_digit_classes', 0),
                    'two_char_classes': combined_manual_patterns.get('two_digit_classes', 0),
                    'three_char_classes': combined_manual_patterns.get('three_digit_classes', 0),
                    'single_methods': combined_manual_patterns.get('single_methods', 0),
                    'logical_classes': logical_classes_for_eval
                }
            
            for rule_type in rule_types:
                try:
                    # Select applicable rule for multi-DEX
                    selected_rule = select_applicable_rule(
                        rules_config, modality, analysis_method, 
                        logical_classes_for_eval, total_dex_count, rule_type
                    )
                    
                    if not selected_rule:
                        safe_print(f"   ❌ No {rule_type} multi-DEX rule applicable for {analysis_method}")
                        continue
                    
                    safe_print(f"   ✅ Selected {rule_type} multi-DEX rule: {selected_rule.get('description', 'Unknown')}")
                    
                    # Evaluate rule against combined patterns
                    evaluation_result = evaluate_rule_against_patterns(
                        selected_rule, pattern_data, logical_classes_for_eval, analysis_method
                    )
                    
                    evaluation_result['rule_type'] = rule_type
                    evaluation_result['analysis_method'] = analysis_method
                    evaluation_result['modality'] = modality
                    evaluation_results.append(evaluation_result)
                    
                    # Print evaluation details
                    safe_print(f"   📊 Multi-DEX rule evaluation:")
                    safe_print(f"      Components passed: {evaluation_result['components_passed']}/{evaluation_result['components_total']}")
                    safe_print(f"      Should trigger: {evaluation_result['should_trigger']}")
                    if evaluation_result['should_trigger']:
                        safe_print(f"      Trigger reason: {evaluation_result['trigger_reason']}")
                    
                    # Track best result (prefer optimal rules)
                    if evaluation_result['should_trigger']:
                        if best_result is None or rule_type == "optimal":
                            best_result = evaluation_result
                            safe_print(f"   🎯 Best multi-DEX trigger: {analysis_method} {rule_type}")
                
                except Exception as rule_error:
                    safe_print(f"   ❌ Error evaluating multi-DEX {analysis_method} {rule_type}: {rule_error}")
                    continue
        
        # Final multi-DEX decision
        if best_result:
            safe_print(f"\n🎯 COMBINED MULTI-DEX DECISION:")
            safe_print(f"{'='*60}")
            safe_print(f"✅ SHOULD TRIGGER: {best_result['analysis_method']} {best_result['rule_type']} multi-DEX rule")
            safe_print(f"📋 Modality: {best_result['modality']}")
            safe_print(f"📋 Total DEX files: {total_dex_count}")
            safe_print(f"📋 Combined analysis successful")
            safe_print(f"📋 Trigger reason: {best_result['trigger_reason']}")
            
            percentage = 100.0
            return percentage, True, best_result, evaluation_results
        else:
            safe_print(f"\n🎯 COMBINED MULTI-DEX DECISION:")
            safe_print(f"{'='*60}")
            safe_print(f"❌ SHOULD NOT TRIGGER: No multi-DEX rules met criteria")
            safe_print(f"📋 Total DEX files: {total_dex_count}")
            safe_print(f"📋 Combined analysis completed")
            
            if evaluation_results:
                max_completion = max(
                    (result['components_passed'] / max(1, result['components_total'])) * 100 
                    for result in evaluation_results
                )
                percentage = max_completion
            else:
                percentage = 50.0  # Basic completion for multi-DEX attempt
            
            return percentage, False, {}, evaluation_results
            
    except Exception as e:
        safe_print(f"❌ Error in multi-DEX rule evaluation: {e}")
        return 0, False, {}, {}

def analyze_single_dex_detailed(dex_file_path, sdk_config=None, total_dex_count=1):
    """
    Perform detailed analysis of a single DEX file.
    Returns (percentage, should_trigger).
    
    Args:
        dex_file_path: Path to DEX file
        sdk_config: Optional SDK configuration dict
        total_dex_count: Total number of DEX files in the APK (for modality determination)
    """
    
    try:
        with open(dex_file_path, 'rb') as f:
            dex_data = f.read()
    except Exception as e:
        safe_print(f"❌ Error reading DEX file: {e}")
        return 0, False
    
    safe_print(f"📊 DEX file size: {len(dex_data):,} bytes")
    
    # Read DEX header to get class_defs_size (like YARA does)
    import struct
    if len(dex_data) >= 0x70:  # Minimum DEX header size
        dex_header_class_defs_size = struct.unpack('<I', dex_data[0x60:0x64])[0]
        safe_print(f"📊 DEX header class_defs_size: {dex_header_class_defs_size:,}")
    else:
        safe_print(f"❌ DEX file too small for header analysis")
        return 0, False
    
    # FIXED: Use EXACT YARA pattern matching logic to ensure consistency
    import re
    
    # Convert to latin-1 string for regex operations (preserves all byte values)
    try:
        data_str = dex_data.decode('latin-1')
    except:
        data_str = str(dex_data)
    
    # DUAL ANALYSIS: Both YARA-strict and Manual inspection patterns
    
    # =============================
    # METHOD 1: EXACT YARA patterns (DEX string table formatting)
    # =============================
    yara_patterns = {}
    
    # Short string patterns - EXACT YARA bytes
    yara_patterns['short_a'] = len(re.findall(r'\x00\x03a\x00', data_str))
    yara_patterns['short_b'] = len(re.findall(r'\x00\x03b\x00', data_str))  
    yara_patterns['short_c'] = len(re.findall(r'\x00\x03c\x00', data_str))
    yara_patterns['short_d'] = len(re.findall(r'\x00\x03d\x00', data_str))
    yara_patterns['short_e'] = len(re.findall(r'\x00\x03e\x00', data_str))
    
    # Single class patterns - EXACT YARA bytes (comprehensive)
    # Look for all single letter classes: La;, Lb;, Lc;, Ld;, Le;, etc.
    single_class_pattern = re.findall(r'L[a-z];\x00', data_str)
    yara_patterns['single_class_total'] = len(single_class_pattern)
    
    # Also look for single character classes with package structure: La/b;, Lc/d;, etc.
    single_class_with_package = re.findall(r'L[a-z]/[a-z];\x00', data_str)
    yara_patterns['single_class_with_package'] = len(single_class_with_package)
    
    # Look for patterns like La/b/c/d; where any part contains single characters
    # This matches the broader manual inspection approach
    complex_single_patterns = re.findall(r'L[a-z]/[^;\x00]*;\x00', data_str)
    yara_patterns['complex_single_class'] = len(complex_single_patterns)
    
    # Combined total for comprehensive single class detection
    # FIXED: Remove double-counting and use correct patterns for YARA consistency
    yara_patterns['single_class_comprehensive'] = yara_patterns['single_class_total']  # Only count true single-letter classes
    
    # DEBUG: Add debug prints to track the 164 count
    safe_print(f"🐛 DEBUG single class counts:")
    safe_print(f"   single_class_total (true L[a-z];): {yara_patterns['single_class_total']}")
    safe_print(f"   single_class_with_package (L[a-z]/[a-z];): {yara_patterns['single_class_with_package']}")
    safe_print(f"   complex_single_class (L[a-z]/[^;]*;): {yara_patterns['complex_single_class']}")
    safe_print(f"   single_class_comprehensive (FIXED): {yara_patterns['single_class_comprehensive']}")
    safe_print(f"   🚨 BUG: Previous calculation was double-counting: {yara_patterns['single_class_with_package'] + yara_patterns['complex_single_class']}")
    
    # Keep individual counters for legacy compatibility
    yara_patterns['single_class_a'] = len(re.findall(r'La;\x00', data_str))
    yara_patterns['single_class_b'] = len(re.findall(r'Lb;\x00', data_str))
    yara_patterns['single_class_c'] = len(re.findall(r'Lc;\x00', data_str))
    
    # Two-character class pattern: { 00 ?? 4C ?? ?? 2F ?? ?? 3B 00 }  // L??/??;
    # This should match classes where both parts are exactly 2 chars: Lab/xy;
    yara_patterns['two_char_class'] = len(re.findall(r'\x00.L..\/..;\x00', data_str, re.DOTALL))
    
    # Three-character class pattern: { 00 ?? 4C ?? ?? ?? 2F ?? ?? ?? 3B 00 }  // L???/???;
    yara_patterns['three_char_class'] = len(re.findall(r'\x00.L...\/.../\;\x00', data_str, re.DOTALL))
    
    # Single method pattern - EXACT YARA bytes
    yara_patterns['single_method'] = len(re.findall(r'\x00\x01[a-z]\x00', data_str))
    
    # Main class pattern: Enhanced to handle malformed classes (multiple L prefixes)
    yara_patterns['class_pattern'] = len(re.findall(r'\x00[\x02-\x7F]L+[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    
    # SDK exclusion patterns - Enhanced to handle malformed classes (LLcom/google/, LLLcom/google/, etc.)
    # Original pattern: \x00[\x02-\x7F]L... but malformed DEX can have multiple L's
    yara_patterns['google_class'] = len(re.findall(r'\x00[\x02-\x7F]L+com/google/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['com_android_class'] = len(re.findall(r'\x00[\x02-\x7F]L+com/android/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['android_class'] = len(re.findall(r'\x00[\x02-\x7F]L+android/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['androidx_class'] = len(re.findall(r'\x00[\x02-\x7F]L+androidx/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['kotlin_class'] = len(re.findall(r'\x00[\x02-\x7F]L+kotlin/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['java_class'] = len(re.findall(r'\x00[\x02-\x7F]L+java/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['kotlinx_class'] = len(re.findall(r'\x00[\x02-\x7F]L+kotlinx/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['dalvik_class'] = len(re.findall(r'\x00[\x02-\x7F]L+dalvik/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['org_class'] = len(re.findall(r'\x00[\x02-\x7F]L+org/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    # Additional exclusions synchronized with YARA obfuscators.yara massive_name_obfuscation rule
    yara_patterns['retrofit2_class'] = len(re.findall(r'\x00[\x02-\x7F]L+retrofit2/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['ro_class'] = len(re.findall(r'\x00[\x02-\x7F]L+ro/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['view_class'] = len(re.findall(r'\x00[\x02-\x7F]L+view/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['persist_class'] = len(re.findall(r'\x00[\x02-\x7F]L+persist/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['sun_class'] = len(re.findall(r'\x00[\x02-\x7F]L+sun/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['guava_class'] = len(re.findall(r'\x00[\x02-\x7F]L+guava/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['vnd_android_class'] = len(re.findall(r'\x00[\x02-\x7F]L+vnd/android/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['schemas_android_class'] = len(re.findall(r'\x00[\x02-\x7F]L+schemas/android/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['in_collections_class'] = len(re.findall(r'\x00[\x02-\x7F]L+in/collections/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['media_class'] = len(re.findall(r'\x00[\x02-\x7F]L+media/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    
    # Enhanced YARA patterns for custom SDK detection (string table format)
    custom_sdk_classes_yara = 0
    if sdk_config:
        custom_sdk_classes = sdk_config.get('sdk_classes', [])
        
        # Handle both old format (list of strings) and new format (list of objects)
        if custom_sdk_classes and isinstance(custom_sdk_classes[0], dict):
            # New format: [{"pattern": "com/fasterxml", "class_count": 8}, ...]
            custom_patterns = [item['pattern'] for item in custom_sdk_classes]
        else:
            # Old format: ["com/fasterxml", "com/google/gson", ...]
            custom_patterns = custom_sdk_classes
        
        # Add YARA pattern matching for custom SDK classes
        for pattern in custom_patterns:
            if pattern:
                # Convert pattern to YARA string table format: \x00[\x02-\x7F]L+pattern/...;\x00
                if pattern.startswith('L'):
                    # Pattern already has L prefix: Lcom/fasterxml
                    escaped_pattern = re.escape(pattern[1:])  # Remove L for escaping
                    yara_pattern = f'\\x00[\\x02-\\x7F]L+{escaped_pattern}/[a-zA-Z0-9\\$\\/_-]+;\\x00'
                else:
                    # Pattern doesn't have L prefix: com/fasterxml
                    escaped_pattern = re.escape(pattern)
                    yara_pattern = f'\\x00[\\x02-\\x7F]L+{escaped_pattern}/[a-zA-Z0-9\\$\\/_-]+;\\x00'
                
                try:
                    # Use raw string and handle multiple L prefixes like other patterns
                    custom_matches = len(re.findall(yara_pattern.encode().decode('unicode_escape'), data_str))
                    custom_sdk_classes_yara += custom_matches
                    safe_print(f"   🔍 Custom SDK pattern '{pattern}': {custom_matches} matches")
                except re.error as e:
                    safe_print(f"   ⚠️ Invalid custom SDK pattern '{pattern}': {e}")
                    continue
    
    # Legitimate short pattern - EXACT YARA regex
    yara_patterns['legitimate_short'] = len(re.findall(r'L(io|os|ui|vm|db|js|sx|tv|ai|ar|vr|3d|r|app|net|xml|api|gui|jwt|ssl|tls|rsa|aes|des|md5|sha|url|uri|css|dom|xml|sql|tcp|udp|ftp|ssh|git|svn|cvs|yml|pdf|jpg|png|gif|bmp|ico|zip|tar|rar|log|tmp|bin|lib|jar|war|ear|dex|oat|odex|vdex|art)/', data_str))
    
    # Enhanced YARA patterns for custom SDK detection (string table format)
    custom_sdk_classes_yara = 0
    custom_legitimate_yara = 0
    
    if sdk_config:
        custom_sdk_classes = sdk_config.get('sdk_classes', [])
        custom_legitimate_classes = sdk_config.get('legitimate_classes', [])
        
        # Handle both old format (list of strings) and new format (list of objects)
        if custom_sdk_classes and isinstance(custom_sdk_classes[0], dict):
            # New format: [{"pattern": "com/fasterxml", "class_count": 8}, ...]
            custom_patterns = [item['pattern'] for item in custom_sdk_classes]
        else:
            # Old format: ["com/fasterxml", "com/google/gson", ...]
            custom_patterns = custom_sdk_classes
        
        # Add YARA pattern matching for custom SDK classes
        for pattern in custom_patterns:
            if pattern:
                # Convert pattern to YARA string table format: \x00[\x02-\x7F]L+pattern/...;\x00
                if pattern.startswith('L'):
                    # Pattern already has L prefix: Lcom/fasterxml
                    escaped_pattern = re.escape(pattern[1:])  # Remove L for escaping
                    yara_pattern = f'\\x00[\\x02-\\x7F]L+{escaped_pattern}/[a-zA-Z0-9\\$\\/_-]+;\\x00'
                else:
                    # Pattern doesn't have L prefix: com/fasterxml
                    escaped_pattern = re.escape(pattern)
                    yara_pattern = f'\\x00[\\x02-\\x7F]L+{escaped_pattern}/[a-zA-Z0-9\\$\\/_-]+;\\x00'
                
                try:
                    # Use raw string and handle multiple L prefixes like other patterns
                    custom_matches = len(re.findall(yara_pattern.encode().decode('unicode_escape'), data_str))
                    custom_sdk_classes_yara += custom_matches
                    safe_print(f"   🔍 Custom SDK pattern '{pattern}': {custom_matches} matches")
                except re.error as e:
                    safe_print(f"   ⚠️ Invalid custom SDK pattern '{pattern}': {e}")
                    continue
        
        # Add YARA pattern matching for custom legitimate classes
        for pattern in custom_legitimate_classes:
            if pattern:
                # Convert to YARA pattern format
                if pattern.startswith('L'):
                    escaped_pattern = re.escape(pattern[1:])  # Remove L for escaping
                    yara_pattern = f'L{escaped_pattern}/'
                else:
                    escaped_pattern = re.escape(pattern)
                    yara_pattern = f'L{escaped_pattern}/'
                
                try:
                    custom_matches = len(re.findall(yara_pattern, data_str))
                    custom_legitimate_yara += custom_matches
                    safe_print(f"   🔍 Custom legitimate pattern '{pattern}': {custom_matches} matches")
                except re.error as e:
                    safe_print(f"   ⚠️ Invalid custom legitimate pattern '{pattern}': {e}")
                    continue
    
    yara_patterns['custom_legitimate'] = custom_legitimate_yara
    yara_patterns['custom_sdk_classes'] = custom_sdk_classes_yara
    
    # =============================
    # METHOD 2: MANUAL INSPECTION patterns (broader, no strict DEX formatting)
    # =============================
    manual_patterns = {}
    
    # Find ALL class patterns (enhanced to handle malformed classes with multiple L prefixes)
    all_classes = re.findall(r'L+[a-zA-Z0-9\$_/]+;', data_str)
    unique_classes = list(set(all_classes))
    
    # PHASE 1: OBFUSCATION PATTERN ANALYSIS (count patterns from ALL classes for rule detection)
    # This analysis counts obfuscation patterns without filtering - needed for obfuscation rules
    obfuscation_single_classes = []
    obfuscation_double_classes = []
    obfuscation_triple_classes = []
    
    for class_name in unique_classes:
        # Remove 'L' prefix and ';' suffix
        clean_name = class_name[1:-1] if class_name.startswith('L') and class_name.endswith(';') else class_name
        
        # Analyze different patterns for obfuscation detection
        if '/' in clean_name:
            # Package structure: analyze each part for single characters
            parts = clean_name.split('/')
            
            # Count single character parts (any part that is exactly 1 character)
            single_char_parts = [part for part in parts if len(part) == 1 and part.isalpha()]
            if single_char_parts:
                obfuscation_single_classes.append(class_name)
            
            # Check for two-digit patterns like: ab/cd, xy/zw (EXACTLY 2 parts, each 2 chars)
            if (len(parts) == 2 and 
                len(parts[0]) == 2 and len(parts[1]) == 2 and
                parts[0].isalpha() and parts[1].isalpha()):
                obfuscation_double_classes.append(class_name)
            
            # Check for three-digit patterns like: abc/def, xyz/uvw (EXACTLY 2 parts, each 3 chars)
            elif (len(parts) == 2 and 
                  len(parts[0]) == 3 and len(parts[1]) == 3 and
                  parts[0].isalpha() and parts[1].isalpha()):
                obfuscation_triple_classes.append(class_name)
        
        else:
            # No package structure - analyze direct class name
            if len(clean_name) == 2 and clean_name.isalpha():
                obfuscation_double_classes.append(class_name)
            elif len(clean_name) == 3 and clean_name.isalpha():
                obfuscation_triple_classes.append(class_name)
            elif len(clean_name) == 1 and clean_name.isalpha():
                obfuscation_single_classes.append(class_name)
    
    # Store obfuscation counts for rule analysis
    manual_patterns['single_digit_classes'] = len(obfuscation_single_classes)
    manual_patterns['two_digit_classes'] = len(obfuscation_double_classes)
    manual_patterns['three_digit_classes'] = len(obfuscation_triple_classes)
    
    safe_print(f"   📊 Obfuscation Pattern Analysis (from {len(unique_classes):,} total classes):")
    safe_print(f"      Single-char obfuscation patterns: {len(obfuscation_single_classes):,}")
    safe_print(f"      Double-char obfuscation patterns: {len(obfuscation_double_classes):,}")
    safe_print(f"      Triple-char obfuscation patterns: {len(obfuscation_triple_classes):,}")
    
    # PHASE 2: SDK DISCOVERY ANALYSIS (apply filtering for accurate non-discoverable SDK detection)
    
    # SDK patterns (for exclusion in manual analysis)
    sdk_patterns = [
        r'^Lcom/google/',
        r'^Lcom/android/',
        r'^Landroid/',
        r'^Landroidx/',
        r'^Lkotlin/',
        r'^Ljava/',
        r'^Lkotlinx/',
        r'^Ldalvik/',
        r'^Lorg/',  # Simplified to match any org package (includes apache, json, xml, w3c, etc.)
        r'^Ljavax/',
        r'^Lsun/',
        # Additional exclusions synchronized with YARA obfuscators.yara massive_name_obfuscation rule
        r'^Lretrofit2/',
        r'^Lro/',
        r'^Lview/',
        r'^Lpersist/',
        r'^Lguava/',
        r'^Lvnd/android/',
        r'^Lschemas/android/',
        r'^Lin/collections/',
        r'^Lmedia/'
    ]
    
    # Legitimate short patterns (not obfuscated)
    legitimate_patterns = [
        r'^L(io|os|ui|vm|db|js|sx|tv|ai|ar|vr|3d|r|app|net|xml|api|gui)/',
        r'^L(jwt|ssl|tls|rsa|aes|des|md5|sha|url|uri|css|dom|sql)/',
        r'^L(tcp|udp|ftp|ssh|git|svn|cvs|yml|pdf|jpg|png|gif|bmp)/',
        r'^L(ico|zip|tar|rar|log|tmp|bin|lib|jar|war|ear|dex)/',
        r'^L(oat|odex|vdex|art)/'
    ]
    
    # Add custom SDK patterns if provided
    if sdk_config:
        custom_sdk_classes = sdk_config.get('sdk_classes', [])
        custom_legitimate_classes = sdk_config.get('legitimate_classes', [])
        
        # Handle both old format (list of strings) and new format (list of objects with pattern/class_count)
        if custom_sdk_classes and isinstance(custom_sdk_classes[0], dict):
            # New format: [{"pattern": "com/fasterxml", "class_count": 8}, ...]
            custom_patterns = [item['pattern'] for item in custom_sdk_classes]
            total_custom_classes = sum(item.get('class_count', 1) for item in custom_sdk_classes)
            safe_print(f"📋 Adding {len(custom_patterns)} custom SDK patterns ({total_custom_classes} total classes)")
        else:
            # Old format: ["com/fasterxml", "com/google/gson", ...]
            custom_patterns = custom_sdk_classes
            safe_print(f"📋 Adding {len(custom_patterns)} custom SDK class patterns")
        
        if custom_legitimate_classes:
            safe_print(f"📋 Adding {len(custom_legitimate_classes)} custom legitimate class patterns")
        
        # Add custom SDK patterns - ensure they start with L and end with /
        for pattern in custom_patterns:
            if pattern and not pattern.startswith('^'):
                # Convert class pattern to regex pattern
                if pattern.startswith('L') and pattern.endswith('/'):
                    regex_pattern = f'^{re.escape(pattern)}'
                elif pattern.startswith('L'):
                    regex_pattern = f'^{re.escape(pattern)}/'
                else:
                    regex_pattern = f'^L{re.escape(pattern)}/'
                sdk_patterns.append(regex_pattern)
        
        # Add custom legitimate patterns
        for pattern in custom_legitimate_classes:
            if pattern and not pattern.startswith('^'):
                # Convert class pattern to regex pattern
                if pattern.startswith('L') and pattern.endswith('/'):
                    regex_pattern = f'^{re.escape(pattern)}'
                elif pattern.startswith('L'):
                    regex_pattern = f'^{re.escape(pattern)}/'
                else:
                    regex_pattern = f'^L{re.escape(pattern)}/'
                legitimate_patterns.append(regex_pattern)
    
    def is_sdk_class(class_name):
        """Check if class is from SDK (including custom SDK patterns)."""
        # Normalize malformed class names (handle multiple L prefixes like LLcom/google/)
        normalized_name = class_name
        if class_name.startswith('L'):
            # Remove extra L prefixes - find the first non-L character or valid package start
            i = 0
            while i < len(class_name) and class_name[i] == 'L':
                i += 1
            if i > 1:  # If we found multiple L's
                normalized_name = 'L' + class_name[i:]
        
        for pattern in sdk_patterns:
            if re.match(pattern, normalized_name):
                return True
        return False
    
    def is_legitimate_short(class_name):
        """Check if class is legitimate short name (including custom patterns)."""
        for pattern in legitimate_patterns:
            if re.match(pattern, class_name):
                return True
        return False
    
    def is_app_specific_class(class_name):
        """Check if class belongs to the main application (not third-party SDK)"""
        # This is a heuristic - you might want to customize this based on your needs
        app_specific_patterns = [
            r'^Lcom/zebra/',      # Zebra-specific classes
            r'^Lcom/symbol/',     # Symbol-specific classes
            r'^Lcom/motorolasolutions/',  # Motorola Solutions classes
            # Add other app-specific patterns as needed
        ]
        
        # Normalize malformed class names
        normalized_name = class_name
        if class_name.startswith('L'):
            i = 0
            while i < len(class_name) and class_name[i] == 'L':
                i += 1
            if i > 1:
                normalized_name = 'L' + class_name[i:]
        
        for pattern in app_specific_patterns:
            if re.match(pattern, normalized_name):
                return True
        return False
    
    # Helper function to check for very short classes (FIXED to match zebra_sdk_discovery.py logic)
    def is_very_short_class(class_name):
        """Check if class has very short (1-3 character) package or class names."""
        if not class_name.startswith('L') or not class_name.endswith(';'):
            return False
        
        # Remove L and ; prefix/suffix
        class_path = class_name[1:-1]
        
        # Split by / to get package components
        parts = class_path.split('/')
        
        # Check if any package component is 1-3 characters (excluding legitimate ones)
        for part in parts:
            if len(part) <= 3:
                # Allow some legitimate 1-3 char components (EXACT MATCH to zebra_sdk_discovery.py)
                legitimate_short_components = {
                    'io', 'os', 'ui', 'vm', 'db', 'js', 'tv', 'ai', 'ar', 'vr', '3d',
                    'www', 'ftp', 'cdn', 'aws', 'gcp', 'api', 'sdk', 'ide', 'jvm', 'jre', 'jdk',
                    'gcc', 'npm', 'pip', 'git', 'svn', 'exe', 'dll', 'png', 'jpg', 'gif', 'bmp',
                    'svg', 'ico', 'mp3', 'mp4', 'avi', 'mov', 'wav', 'ogg', 'zip', 'rar', 'tar',
                    'txt', 'doc', 'pdf', 'xls', 'ppt', 'csv', 'xml', 'sql', 'app', 'net', 'gui',
                    'jwt', 'ssl', 'tls', 'rsa', 'aes', 'des', 'md5', 'sha', 'url', 'uri', 'css',
                    'dom', 'tcp', 'udp', 'ssh', 'yml', 'log', 'tmp', 'bin', 'lib', 'jar', 'war',
                    'ear', 'dex', 'oat', 'art', 'com', 'org', 'net', 'edu', 'gov', 'mil',
                    'osx'  # FIXED: Add Zebra/Symbol OSX package name
                }
                
                if part.lower() not in legitimate_short_components:
                    return True
        
        return False
    
    # Helper function to check for obfuscated patterns (FIXED to match zebra_sdk_discovery.py logic)
    def has_obfuscated_pattern(class_name):
        """Check if class appears to be obfuscated (single letters, numbers, random chars)."""
        if not class_name.startswith('L') or not class_name.endswith(';'):
            return False
        
        class_path = class_name[1:-1]
        parts = class_path.split('/')
        
        # Check for common obfuscation patterns (EXACT MATCH to zebra_sdk_discovery.py)
        for part in parts:
            # Single character components (except legitimate ones)
            if len(part) == 1 and part not in 'iorpabcdefghijklmnqstuvwxyz':
                return True
            
            # All numbers
            if part.isdigit():
                return True
            
            # Mixed random characters (heuristic: mostly consonants or no vowels)
            if len(part) >= 4:
                vowels = sum(1 for c in part.lower() if c in 'aeiou')
                consonants = sum(1 for c in part.lower() if c.isalpha() and c not in 'aeiou')
                # If ratio of consonants to vowels is very high, likely obfuscated
                if vowels == 0 and consonants > 3:
                    return True
                if consonants > 0 and vowels / (consonants + vowels) < 0.15:
                    return True
        
        return False

    # CORRECT IMPLEMENTATION: Filter classes step by step following zebra_sdk_discovery.py logic
    logical_classes_manual = []
    sdk_classes_manual = []
    legitimate_classes_manual = []
    very_short_classes_filtered = 0
    obfuscated_classes_filtered = 0
    
    # Step 1: Filter out SDK classes, legitimate classes, very short classes, and obfuscated classes
    for class_name in unique_classes:
        if is_sdk_class(class_name):
            sdk_classes_manual.append(class_name)
        elif is_legitimate_short(class_name):
            legitimate_classes_manual.append(class_name)
        elif is_very_short_class(class_name):
            very_short_classes_filtered += 1
        elif has_obfuscated_pattern(class_name):
            obfuscated_classes_filtered += 1
        else:
            logical_classes_manual.append(class_name)
    
    # Step 2: Use zebra_sdk_discovery.py to get accurate non-discoverable SDK class count
    # Import the functions we need
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("zebra_sdk_discovery", "zebra_sdk_discovery.py")
        zebra_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(zebra_module)
        
        # Use the proper zebra SDK discovery logic
        non_discovered_sdk_classes_manual, zebra_symbol_classes = zebra_module.filter_zebra_symbol_classes(logical_classes_manual)
        
        safe_print(f"   📊 Manual analysis - using zebra_sdk_discovery.py logic:")
        safe_print(f"      Total unique classes: {len(unique_classes):,}")
        safe_print(f"      SDK classes excluded: {len(sdk_classes_manual):,}")
        safe_print(f"      Legitimate classes excluded: {len(legitimate_classes_manual):,}")
        safe_print(f"      Very short classes excluded: {very_short_classes_filtered:,}")
        safe_print(f"      Obfuscated classes excluded: {obfuscated_classes_filtered:,}")
        safe_print(f"      Logical classes (clean): {len(logical_classes_manual):,}")
        safe_print(f"      Zebra/Symbol classes: {len(zebra_symbol_classes):,}")
        safe_print(f"      Non-discovered SDK classes: {len(non_discovered_sdk_classes_manual):,}")
        
    except Exception as e:
        safe_print(f"   ⚠️ Could not import zebra_sdk_discovery.py: {e}")
        safe_print(f"   📊 Manual analysis - fallback to simple app-specific filtering:")
        
        # Fallback to simple filtering if zebra_sdk_discovery is not available
        non_discovered_sdk_classes_manual = []
        app_specific_classes_manual = []
        zebra_symbol_classes = []  # Initialize for fallback case
        
        for class_name in logical_classes_manual:
            if is_app_specific_class(class_name):
                app_specific_classes_manual.append(class_name)
                zebra_symbol_classes.append(class_name)  # Treat app-specific as zebra/symbol
            else:
                non_discovered_sdk_classes_manual.append(class_name)
        
        safe_print(f"      Total unique classes: {len(unique_classes):,}")
        safe_print(f"      SDK classes excluded: {len(sdk_classes_manual):,}")
        safe_print(f"      Legitimate classes excluded: {len(legitimate_classes_manual):,}")
        safe_print(f"      Very short classes excluded: {very_short_classes_filtered:,}")
        safe_print(f"      Obfuscated classes excluded: {obfuscated_classes_filtered:,}")
        safe_print(f"      Logical classes (clean): {len(logical_classes_manual):,}")
        safe_print(f"      App-specific classes: {len(app_specific_classes_manual):,}")
        safe_print(f"      Non-discovered SDK classes: {len(non_discovered_sdk_classes_manual):,}")
    
    # Print a simple summary of non-discovered SDK classes (not detailed breakdown)
    if len(non_discovered_sdk_classes_manual) > 0:
        safe_print(f"\n   📊 Non-discovered SDK classes summary: {len(non_discovered_sdk_classes_manual):,} classes found")
        safe_print(f"   💡 These classes passed all filtering steps and are not app-specific classes")
        safe_print(f"   🔍 Use zebra_sdk_discovery.py for detailed analysis and pattern generation")
    else:
        safe_print(f"\n   ✅ No non-discovered SDK classes found")
    
    # OBFUSCATION ANALYSIS: Use the counts from PHASE 1 (already calculated above)
    # Note: We use the obfuscation patterns counted from ALL classes (before filtering)
    # This is correct for obfuscation rule detection
    
    # Manual analysis for method names (look for single character method names in any context)
    single_char_methods = re.findall(r'[^a-zA-Z][a-z]\x00', data_str)
    manual_single_methods = [m for m in single_char_methods if len(m.strip('\x00')) == 1]
    
    # Enhanced manual analysis for short strings - targeting actual DEX string table entries
    # Method 1: DEX string table format detection (mimicking YARA patterns)
    manual_short_strings_dex_format = []
    for char_code in [0x61, 0x62, 0x63, 0x64, 0x65]:  # a, b, c, d, e
        # Pattern: \x00\x03<char>\x00 (length-prefixed string format)
        pattern = bytes([0x00, 0x03, char_code, 0x00])
        manual_short_strings_dex_format.extend([m.start() for m in re.finditer(re.escape(pattern), data_str.encode('latin-1'))])
    
    # Method 2: String table context detection (more comprehensive)
    # Look for single character strings in string table context with various length prefixes
    manual_short_strings_context = []
    for char_code in [0x61, 0x62, 0x63, 0x64, 0x65]:  # a, b, c, d, e
        # Pattern variations: length prefix + char + null terminator
        patterns = [
            bytes([0x00, 0x01, char_code, 0x00]),  # \x00\x01<char>\x00 (length 1)
            bytes([0x01, char_code, 0x00]),        # \x01<char>\x00 (ULEB128 length 1)
            bytes([0x00, 0x03, char_code, 0x00]),  # \x00\x03<char>\x00 (length 3, YARA pattern)
        ]
        for pattern in patterns:
            manual_short_strings_context.extend([m.start() for m in re.finditer(re.escape(pattern), data_str.encode('latin-1'))])
    
    # Method 3: Method/field name context detection
    # Look for single chars in method/field name contexts (more targeted than original)
    manual_short_strings_names = []
    # Pattern: method/field signature containing single char names
    name_patterns = [
        rb'\x00\x01[a-e]\x00',  # Single char method/field names
        rb'[a-e]\x00.*?\(',      # Single char followed by method signature
        rb'L[a-e];',             # Single char class references
        rb'/[a-e];',             # Single char in package context
    ]
    for pattern in name_patterns:
        matches = re.finditer(pattern, data_str.encode('latin-1'))
        manual_short_strings_names.extend([m.start() for m in matches])
    
    # Method 4: Conservative approach - string literals only
    # Look for actual string literals that are single characters a-e
    manual_short_strings_literals = []
    # Pattern: string table entries that are exactly single characters
    for char in ['a', 'b', 'c', 'd', 'e']:
        # Look for string table pattern: length + char + terminator
        literal_patterns = [
            char.encode() + b'\x00',  # char + null terminator
            b'\x01' + char.encode() + b'\x00',  # length 1 + char + null
        ]
        for pattern in literal_patterns:
            matches = re.finditer(re.escape(pattern), data_str.encode('latin-1'))
            manual_short_strings_literals.extend([m.start() for m in matches])
    
    # Combine results and remove duplicates
    all_short_strings = set(manual_short_strings_dex_format + manual_short_strings_context + 
                           manual_short_strings_names + manual_short_strings_literals)
    manual_short_strings = list(all_short_strings)
    
    # Enhanced debugging for short string detection methods
    safe_print(f"🔍 DEBUG: Enhanced short string detection breakdown:")
    safe_print(f"   DEX format patterns (\\x00\\x03<char>\\x00): {len(manual_short_strings_dex_format)}")
    safe_print(f"   Context patterns (various length prefixes): {len(manual_short_strings_context)}")
    safe_print(f"   Name patterns (method/field/class contexts): {len(manual_short_strings_names)}")
    safe_print(f"   String literals (actual string table entries): {len(manual_short_strings_literals)}")
    safe_print(f"   Combined unique positions: {len(manual_short_strings)}")
    
    # Fallback to original broad method if enhanced methods find nothing
    if len(manual_short_strings) == 0:
        # Original broad method as fallback
        manual_short_strings_broad = re.findall(r'[a-e]', data_str)
        manual_short_strings = manual_short_strings_broad
        safe_print(f"🔍 DEBUG: Enhanced short string detection found 0 matches, falling back to broad method: {len(manual_short_strings)} matches")
    else:
        # Also compare with original broad method for insight
        manual_short_strings_broad = re.findall(r'[a-e]', data_str)
        safe_print(f"🔍 DEBUG: Enhanced vs Original comparison: {len(manual_short_strings)} enhanced vs {len(manual_short_strings_broad)} broad (reduction factor: {len(manual_short_strings_broad)/max(1,len(manual_short_strings)):.1f}x)")
    
    # Store manual pattern counts
    manual_patterns['total_classes'] = len(unique_classes)
    manual_patterns['logical_classes'] = len(logical_classes_manual)
    manual_patterns['sdk_classes'] = len(sdk_classes_manual)
    manual_patterns['legitimate_classes'] = len(legitimate_classes_manual)
    manual_patterns['non_discovered_sdk_classes'] = len(non_discovered_sdk_classes_manual)
    manual_patterns['zebra_symbol_classes'] = len(zebra_symbol_classes)  # FIXED: Missing zebra symbol classes storage
    # Note: single/double/triple digit classes already set in PHASE 1 above
    
    # Debug output for single class detection - always show when no single classes found
    if manual_patterns['single_digit_classes'] == 0:
        safe_print("🔍 DEBUG: No single character classes found. Showing first 20 logical classes for inspection:")
        for i, class_name in enumerate(logical_classes_manual[:20]):
            clean_name = class_name[1:-1]  # Remove L and ;
            safe_print(f"   Class {i+1}: {class_name} -> '{clean_name}'")
        
        # Also show any classes that might look like single chars
        potential_singles = [c for c in logical_classes_manual if len(c) <= 4]  # L + char + ;
        if potential_singles:
            safe_print(f"🔍 DEBUG: Found {len(potential_singles)} short classes (length <= 4):")
            for c in potential_singles[:10]:
                safe_print(f"   Short class: {c}")
        
        # Show some obfuscated single char classes that were filtered out
        if len(obfuscation_single_classes) > 0:
            safe_print(f"🔍 DEBUG: But found {len(obfuscation_single_classes)} obfuscated single-char classes (filtered for SDK analysis):")
            for c in sorted(obfuscation_single_classes[:10]):
                safe_print(f"   Obfuscated: {c}")
    
    manual_patterns['single_methods'] = len(manual_single_methods)
    manual_patterns['short_strings'] = len(manual_short_strings)
    
    # For backward compatibility, use YARA patterns as primary
    patterns = yara_patterns
    
    # Calculate using EXACT YARA logic - FIXED to match YARA's dex.header.class_defs_size
    total_classes_regex = patterns['class_pattern']  # Keep for comparison
    total_classes_dex_header = dex_header_class_defs_size  # Use DEX header like YARA
    
    # SDK classes calculation synchronized with YARA obfuscators.yara massive_name_obfuscation rule
    # Include custom SDK patterns in calculation
    sdk_classes_raw = (patterns['google_class'] + patterns['com_android_class'] + patterns['android_class'] + patterns['androidx_class'] + 
                       patterns['kotlin_class'] + patterns['java_class'] + patterns['kotlinx_class'] + 
                       patterns['dalvik_class'] + patterns['org_class'] + patterns['retrofit2_class'] + 
                       patterns['ro_class'] + patterns['view_class'] + patterns['persist_class'] + 
                       patterns['sun_class'] + patterns['guava_class'] + patterns['vnd_android_class'] + 
                       patterns['schemas_android_class'] + patterns['in_collections_class'] + 
                       patterns['media_class'] + patterns['legitimate_short'] + patterns['custom_legitimate'] + 
                       patterns['custom_sdk_classes'])  # Include custom SDK patterns
    
    # CRITICAL FIX: Cap SDK classes to never exceed total classes (prevents negative logical classes)
    # Root cause: YARA patterns count string table occurrences, not unique class definitions
    sdk_classes = min(sdk_classes_raw, total_classes_dex_header)
    
    # YARA uses dex.header.class_defs_size for total classes but regex patterns for SDK classes
    # NOTE: YARA "logical_classes" = total_classes - sdk_classes (simplified approximation)
    # This differs from true logical classes which also exclude obfuscated patterns
    yara_approximate_logical_classes = max(0, total_classes_dex_header - sdk_classes)
    
    # Note: YARA method cannot calculate accurate non-discovered SDK classes
    # because it lacks sophisticated filtering of obfuscated patterns.
    # Only the manual analysis with zebra_sdk_discovery.py provides accurate calculations.
    
    # Debug logging for the PhotoTable case
    if sdk_classes_raw != sdk_classes:
        safe_print(f"   🔧 FIX APPLIED: SDK classes capped from {sdk_classes_raw:,} to {sdk_classes:,}")
        safe_print(f"   📊 Reason: SDK count exceeded total classes ({total_classes_dex_header:,})")
    
    if yara_approximate_logical_classes == 0 and total_classes_dex_header > 0:
        safe_print(f"   ⚠️  WARNING: All {total_classes_dex_header:,} classes detected as SDK classes")
        safe_print(f"   💡 Non-SDK classes (like zebra.util) may be miscategorized as SDK")
        safe_print(f"   🔍 Custom SDK patterns contributed: {patterns['custom_sdk_classes']:,} classes")
    
    safe_print(f"   📊 Custom SDK detection: {patterns['custom_sdk_classes']:,} classes")
    safe_print(f"   📊 Custom legitimate detection: {patterns['custom_legitimate']:,} classes")
    
    # Pattern-specific counts using EXACT YARA logic
    short_strings = (patterns['short_a'] + patterns['short_b'] + patterns['short_c'] + 
                     patterns['short_d'] + patterns['short_e'])
    single_classes = patterns['single_class_comprehensive']  # Use comprehensive total including package structure
    two_char_classes = patterns['two_char_class']
    three_char_classes = patterns['three_char_class']
    single_methods = patterns['single_method']  # Use EXACT YARA pattern instead of old method
    
    # Display raw counts using BOTH YARA and Manual analysis
    safe_print(f"\n📈 Raw Pattern Counts:")
    safe_print(f"   ═══════════════════════════════════════════════")
    safe_print(f"   📊 YARA-STRICT Analysis (DEX string table format):")
    safe_print(f"   ───────────────────────────────────────────────")
    safe_print(f"   Total classes (L...;): {total_classes_regex:,}")
    safe_print(f"   DEX header classes: {total_classes_dex_header:,}")
    safe_print(f"   SDK classes: {sdk_classes:,}")
    safe_print(f"   Legitimate short: {patterns['legitimate_short']:,}")
    safe_print(f"   Custom SDK classes: {patterns['custom_sdk_classes']:,}")
    safe_print(f"   Custom legitimate: {patterns['custom_legitimate']:,}")
    safe_print(f"   Logical classes: {yara_approximate_logical_classes:,}")
    safe_print(f"   Short strings (a-e): {short_strings:,}")
    safe_print(f"   Single class names: {single_classes:,}")
    safe_print(f"   Two-char classes: {two_char_classes:,}")
    safe_print(f"   Three-char classes: {three_char_classes:,}")
    safe_print(f"   Single methods: {single_methods:,}")
    
    safe_print(f"\n   📋 MANUAL INSPECTION Analysis (broader patterns):")
    safe_print(f"   ───────────────────────────────────────────────")
    safe_print(f"   Total unique classes: {manual_patterns['total_classes']:,}")
    safe_print(f"   SDK classes (excluded): {manual_patterns['sdk_classes']:,}")
    safe_print(f"   Legitimate short (excluded): {manual_patterns['legitimate_classes']:,}")
    safe_print(f"   Logical classes analyzed: {manual_patterns['logical_classes']:,}")
    safe_print(f"   Non-discovered SDK classes: {manual_patterns['non_discovered_sdk_classes']:,}")
    safe_print(f"   Single-digit classes: {manual_patterns['single_digit_classes']:,}")
    safe_print(f"   Two-digit classes: {manual_patterns['two_digit_classes']:,}")
    safe_print(f"   Three-digit classes: {manual_patterns['three_digit_classes']:,}")
    safe_print(f"   Single-char methods: {manual_patterns['single_methods']:,}")
    safe_print(f"   Short strings (a-e): {manual_patterns['short_strings']:,}")
    
    safe_print(f"\n   🔍 COMPARISON (Manual vs YARA-strict):")
    safe_print(f"   ───────────────────────────────────────")
    manual_two_ratio = (manual_patterns['two_digit_classes'] / two_char_classes) if two_char_classes > 0 else float('inf')
    manual_method_ratio = (manual_patterns['single_methods'] / single_methods) if single_methods > 0 else float('inf')
    manual_short_ratio = (manual_patterns['short_strings'] / short_strings) if short_strings > 0 else float('inf')
    manual_single_class_ratio = (manual_patterns['single_digit_classes'] / single_classes) if single_classes > 0 else float('inf')
    manual_three_char_ratio = (manual_patterns['three_digit_classes'] / three_char_classes) if three_char_classes > 0 else float('inf')
    
    safe_print(f"   📊 Pattern Detection Comparison:")
    safe_print(f"   Short strings (a-e): {manual_patterns['short_strings']:,} vs {short_strings:,} ({manual_short_ratio:.1f}x)")
    safe_print(f"   Single classes:      {manual_patterns['single_digit_classes']:,} vs {single_classes:,} ({manual_single_class_ratio:.1f}x)")
    safe_print(f"   Two-digit classes:   {manual_patterns['two_digit_classes']:,} vs {two_char_classes:,} ({manual_two_ratio:.1f}x)")
    safe_print(f"   Three-char classes:  {manual_patterns['three_digit_classes']:,} vs {three_char_classes:,} ({manual_three_char_ratio:.1f}x)")
    safe_print(f"   Single methods:      {manual_patterns['single_methods']:,} vs {single_methods:,} ({manual_method_ratio:.1f}x)")
    safe_print(f"   ")
    safe_print(f"   🎯 Key Detection Gaps:")
    safe_print(f"   Short strings gap:   {manual_patterns['short_strings'] - short_strings:,} patterns missed by YARA")
    safe_print(f"   Single classes gap:  {manual_patterns['single_digit_classes'] - single_classes:,} classes missed by YARA")
    safe_print(f"   Two-digit gap:       {manual_patterns['two_digit_classes'] - two_char_classes:,} classes missed by YARA")
    safe_print(f"   Three-char gap:      {manual_patterns['three_digit_classes'] - three_char_classes:,} classes missed by YARA")
    safe_print(f"   Single methods gap:  {manual_patterns['single_methods'] - single_methods:,} methods missed by YARA")
    
    # Evaluate conditions step by step - DUAL ANALYSIS
    safe_print(f"\n🎯 Detailed Condition Evaluation:")
    safe_print(f"{'='*60}")
    
    conditions_passed = 0
    total_conditions = 7  # 2 basic + 5 methods
    
    # Basic requirements evaluation for both methods
    req1_min_classes = total_classes_dex_header >= 50  # Common requirement
    req2_logical_classes_yara = yara_approximate_logical_classes > 0
    req2_logical_classes_manual = manual_patterns['logical_classes'] > 0
    
    # Use manual requirements for condition counting (since this is manual analysis)
    if req1_min_classes:
        conditions_passed += 1
    if req2_logical_classes_manual:
        conditions_passed += 1
    
    safe_print(f"Requirement 1 - Min classes: {total_classes_dex_header} >= 50 = {'✅' if req1_min_classes else '❌'}")
    safe_print(f"Requirement 2 - YARA logical classes: {yara_approximate_logical_classes} > 0 = {'✅' if req2_logical_classes_yara else '❌'}")
    safe_print(f"Requirement 2 - Manual logical classes: {manual_patterns['logical_classes']} > 0 = {'✅' if req2_logical_classes_manual else '❌'}")
    
    if not req2_logical_classes_manual:
        safe_print(f"⚠️  Cannot evaluate manual analysis ratios without logical classes")
        percentage = (conditions_passed / total_conditions) * 100
        safe_print(f"\n🎯 Manual Analysis Completion: {percentage:.1f}% ({conditions_passed}/{total_conditions})")
        return percentage, False, {}, {}
    
    # Load obfuscation rules configuration
    try:
        safe_print(f"\n🔄 Loading configurable rule system...")
        rules_config = load_obfuscation_rules_config()
        safe_print(f"✅ Rules config loaded successfully")
        
        # Determine DEX modality and get logical classes for evaluation
        dex_count = total_dex_count  # Use the actual total DEX count from APK
        modality, logical_classes_for_eval = determine_dex_modality(dex_count, yara_approximate_logical_classes, manual_patterns['logical_classes'])
        
        safe_print(f"\n📊 CONFIGURABLE RULE-BASED ANALYSIS:")
        safe_print(f"{'='*60}")
        safe_print(f"📋 DEX Modality: {modality}")
        safe_print(f"📋 Logical classes for evaluation: {logical_classes_for_eval}")
        safe_print(f"📋 DEX count: {dex_count}")
        
        # CONFIGURABLE RULE EVALUATION - BOTH YARA STRICT AND MANUAL INVESTIGATION
        
        # Try both analysis methods and use the best applicable rule
        analysis_methods = ["manual_investigation", "yara_strict"]
        rule_types = ["optimal", "minimal"]  # Check optimal rules first
        
        evaluation_results = []
        best_result = None
        
        for analysis_method in analysis_methods:
            safe_print(f"\n🔍 Evaluating {analysis_method.upper()} rules:")
            safe_print(f"{'─'*50}")
            
            # Select pattern data based on analysis method
            if analysis_method == "yara_strict":
                pattern_data = {
                    'short_strings': short_strings,
                    'single_classes': single_classes,
                    'two_char_classes': two_char_classes,
                    'three_char_classes': three_char_classes,
                    'single_methods': single_methods,
                    'logical_classes': yara_approximate_logical_classes
                }
            else:  # manual_investigation
                pattern_data = {
                    'short_strings': manual_patterns['short_strings'],
                    'single_classes': manual_patterns['single_digit_classes'],
                    'two_char_classes': manual_patterns['two_digit_classes'],
                    'three_char_classes': manual_patterns['three_digit_classes'],
                    'single_methods': manual_patterns['single_methods'],
                    'logical_classes': manual_patterns['logical_classes']
                }
            
            for rule_type in rule_types:
                try:
                    # Select applicable rule
                    selected_rule = select_applicable_rule(
                        rules_config, modality, analysis_method, 
                        logical_classes_for_eval, dex_count, rule_type
                    )
                    
                    if not selected_rule:
                        safe_print(f"   ❌ No {rule_type} rule applicable for {analysis_method}")
                        continue
                    
                    safe_print(f"   ✅ Selected {rule_type} rule: {selected_rule.get('description', 'Unknown')}")
                    
                    # Evaluate rule against patterns
                    evaluation_result = evaluate_rule_against_patterns(
                        selected_rule, pattern_data, logical_classes_for_eval, analysis_method
                    )
                    
                    evaluation_result['rule_type'] = rule_type
                    evaluation_result['analysis_method'] = analysis_method
                    evaluation_result['modality'] = modality
                    evaluation_results.append(evaluation_result)
                    
                    # Print evaluation details
                    safe_print(f"   📊 Rule evaluation result:")
                    safe_print(f"      Components passed: {evaluation_result['components_passed']}/{evaluation_result['components_total']}")
                    safe_print(f"      Should trigger: {evaluation_result['should_trigger']}")
                    if evaluation_result['should_trigger']:
                        safe_print(f"      Trigger reason: {evaluation_result['trigger_reason']}")
                    
                    # Track best result (prefer optimal rules, then minimal)
                    if evaluation_result['should_trigger']:
                        if best_result is None or rule_type == "optimal":
                            best_result = evaluation_result
                            safe_print(f"   🎯 Best trigger result so far: {analysis_method} {rule_type}")
                
                except Exception as rule_error:
                    safe_print(f"   ❌ Error evaluating {analysis_method} {rule_type} rule: {rule_error}")
                    continue
        
        # Final decision based on configurable rules
        if best_result:
            safe_print(f"\n🎯 CONFIGURABLE RULE DECISION:")
            safe_print(f"{'='*60}")
            safe_print(f"✅ SHOULD TRIGGER: {best_result['analysis_method']} {best_result['rule_type']} rule")
            safe_print(f"📋 Modality: {best_result['modality']}")
            safe_print(f"📋 Trigger reason: {best_result['trigger_reason']}")
            safe_print(f"📋 Components passed: {best_result['components_passed']}/{best_result['components_total']}")
            
            # Calculate percentage based on configurable rule success
            percentage = 100.0  # Full completion when rule triggers
            return percentage, True, best_result, evaluation_results
        
        else:
            safe_print(f"\n🎯 CONFIGURABLE RULE DECISION:")
            safe_print(f"{'='*60}")
            safe_print(f"❌ SHOULD NOT TRIGGER: No applicable rules met minimum criteria")
            safe_print(f"📋 Modality: {modality}")
            safe_print(f"📋 Analysis methods tried: {', '.join(analysis_methods)}")
            safe_print(f"📋 Rule types tried: {', '.join(rule_types)}")
            
            if evaluation_results:
                # Find best completion percentage from attempted rules
                max_completion = max(
                    (result['components_passed'] / max(1, result['components_total'])) * 100 
                    for result in evaluation_results
                )
                safe_print(f"📋 Best completion: {max_completion:.1f}%")
                percentage = max_completion
            else:
                # Fallback to basic completion
                percentage = (conditions_passed / total_conditions) * 100
                safe_print(f"📋 Fallback completion: {percentage:.1f}%")
            
            return percentage, False, {}, evaluation_results
        
    except Exception as config_error:
        safe_print(f"❌ Error in configurable rule system: {config_error}")
        import traceback
        traceback.print_exc()
        # Fall back to simple completion calculation
        percentage = (conditions_passed / total_conditions) * 100
        safe_print(f"\n🎯 Manual Analysis Completion: {percentage:.1f}% ({conditions_passed}/{total_conditions})")
        return percentage, False, {}, {}
def load_obfuscation_rules_config(config_path="obfuscation_rules_config.json"):
    """Load obfuscation detection rules from JSON configuration file."""
    try:
        if not os.path.exists(config_path):
            # Create default config if it doesn't exist
            safe_print(f"⚠️ Rules config not found at {config_path}, using built-in defaults")
            return get_default_rules_config()
        
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        safe_print(f"✅ Loaded obfuscation rules config from {config_path}")
        return config
    except Exception as e:
        safe_print(f"❌ Error loading rules config: {e}")
        safe_print("📋 Using built-in default rules")
        return get_default_rules_config()

def get_default_rules_config():
    """Return default rules configuration if config file is not available."""
    return {
        "rules": {
            "single_dex": {
                "yara_strict": {
                    "minimal": {
                        "description": "YARA Strict Minimal rule for single DEX",
                        "applicable_when": {"dex_count": 1, "logical_classes_min": 50},
                        "thresholds": {
                            "short_char": 0, "short_method": 0, "combined_short_rule": 0,
                            "single_char_classes": 0, "two_char_classes": 0, "three_char_classes": 0,
                            "combined_class_rule": 30
                        }
                    },
                    "optimal": {
                        "description": "YARA Strict Optimal rule for single DEX", 
                        "applicable_when": {"dex_count": 1, "logical_classes_min": 50},
                        "thresholds": {
                            "short_char": 20, "short_method": 30, "combined_short_rule": "1.5x",
                            "single_char_classes": 10, "two_char_classes": 15, "three_char_classes": 15,
                            "combined_class_rule": "0.6x"
                        }
                    }
                },
                "manual_investigation": {
                    "minimal": {
                        "description": "Manual Investigation Minimal rule for single DEX",
                        "applicable_when": {"dex_count": 1, "logical_classes_max": 49},
                        "thresholds": {
                            "short_char": 0, "short_method": 0, "combined_short_rule": "20x",
                            "single_char_classes": 0, "two_char_classes": 0, "three_char_classes": 0,
                            "combined_class_rule": 30
                        }
                    },
                    "optimal": {
                        "description": "Manual Investigation Optimal rule for single DEX",
                        "applicable_when": {"dex_count": 1, "logical_classes_min": 50},
                        "thresholds": {
                            "short_char": 20, "short_method": 30, "combined_short_rule": "1.0x",
                            "single_char_classes": 10, "two_char_classes": 15, "three_char_classes": 15,
                            "combined_class_rule": "0.4x"
                        }
                    }
                }
            }
        },
        "rule_evaluation_order": ["small_dex", "single_dex", "multi_dex"],
        "default_rule_type": "optimal"
    }

def determine_dex_modality(dex_count, logical_classes_yara, logical_classes_manual):
    """
    Determine which DEX modality this APK falls into based on DEX count and logical classes.
    
    Returns:
        tuple: (modality_name, logical_classes_for_evaluation)
    """
    # Use manual logical classes as primary since it's more accurate
    logical_classes = logical_classes_manual
    
    # Determine modality based on DEX characteristics
    if logical_classes < 50:
        return "small_dex", logical_classes
    elif dex_count == 1:
        return "single_dex", logical_classes  
    else:  # dex_count > 1
        return "multi_dex", logical_classes

def select_applicable_rule(rules_config, modality, analysis_method, logical_classes, dex_count, rule_type="minimal"):
    """
    Select the appropriate rule based on modality and characteristics.
    
    Args:
        rules_config: Loaded rules configuration
        modality: "single_dex", "multi_dex", or "small_dex"
        analysis_method: "yara_strict" or "manual_investigation"
        logical_classes: Number of logical classes
        dex_count: Number of DEX files
        rule_type: "minimal" or "optimal"
    
    Returns:
        dict: Selected rule configuration or None if not found
    """
    try:
        rules = rules_config.get("rules", {})
        modality_rules = rules.get(modality, {})
        method_rules = modality_rules.get(analysis_method, {})
        selected_rule = method_rules.get(rule_type, {})
        
        if not selected_rule:
            safe_print(f"⚠️ No {rule_type} rule found for {modality}/{analysis_method}")
            return None
        
        # Check if rule is applicable based on conditions
        applicable_when = selected_rule.get("applicable_when", {})
        
        # Check DEX count conditions
        if "dex_count" in applicable_when and dex_count != applicable_when["dex_count"]:
            return None
        if "dex_count_min" in applicable_when and dex_count < applicable_when["dex_count_min"]:
            return None
        if "dex_count_max" in applicable_when and dex_count > applicable_when["dex_count_max"]:
            return None
        
        # Check logical classes conditions
        if "logical_classes_min" in applicable_when and logical_classes < applicable_when["logical_classes_min"]:
            return None
        if "logical_classes_max" in applicable_when and logical_classes > applicable_when["logical_classes_max"]:
            return None
        
        return selected_rule
        
    except Exception as e:
        safe_print(f"❌ Error selecting rule: {e}")
        return None

def evaluate_threshold(threshold_value, actual_value, logical_classes):
    """
    Evaluate whether a threshold is met.
    
    Args:
        threshold_value: Threshold from config (number, "Nx" string, or 0)
        actual_value: Actual measured value
        logical_classes: Number of logical classes for percentage calculations
    
    Returns:
        tuple: (is_met, threshold_description, actual_description)
    """
    if threshold_value == 0:
        # Rule component disabled
        return True, "disabled", f"actual: {actual_value} (not evaluated)"
    
    if isinstance(threshold_value, str) and threshold_value.endswith('x'):
        # Multiplier threshold (e.g., "1.5x" means 1.5 * logical_classes)
        try:
            multiplier = float(threshold_value[:-1])
            threshold_numeric = multiplier * logical_classes
            is_met = actual_value >= threshold_numeric
            threshold_desc = f">= {threshold_numeric:.1f} ({threshold_value} * {logical_classes})"
            actual_desc = f"{actual_value}"
            return is_met, threshold_desc, actual_desc
        except ValueError:
            safe_print(f"⚠️ Invalid multiplier threshold: {threshold_value}")
            return False, f"invalid: {threshold_value}", f"actual: {actual_value}"
    
    # Numeric threshold
    try:
        threshold_numeric = float(threshold_value)
        is_met = actual_value >= threshold_numeric
        threshold_desc = f">= {threshold_numeric}"
        actual_desc = f"{actual_value}"
        return is_met, threshold_desc, actual_desc
    except (ValueError, TypeError):
        safe_print(f"⚠️ Invalid numeric threshold: {threshold_value}")
        return False, f"invalid: {threshold_value}", f"actual: {actual_value}"

def evaluate_rule_against_patterns(rule, patterns, logical_classes, analysis_method):
    """
    Evaluate a rule against detected patterns.
    
    Args:
        rule: Rule configuration dict
        patterns: Detected pattern counts dict
        logical_classes: Number of logical classes
        analysis_method: "yara_strict" or "manual_investigation"
    
    Returns:
        dict: Detailed evaluation results
    """
    if not rule or not patterns:
        return {"rule_applied": False, "error": "Missing rule or patterns"}
    
    thresholds = rule.get("thresholds", {})
    results = {
        "rule_applied": True,
        "rule_description": rule.get("description", "Unknown rule"),
        "analysis_method": analysis_method,
        "logical_classes": logical_classes,
        "individual_components": {},
        "components_passed": 0,
        "components_total": 0,
        "should_trigger": False,
        "trigger_reason": ""
    }
    
    # Map pattern keys based on analysis method
    if analysis_method == "yara_strict":
        pattern_mapping = {
            "short_char": "short_strings",
            "short_method": "single_methods", 
            "single_char_classes": "single_class_comprehensive",
            "two_char_classes": "two_char_logical",
            "three_char_classes": "three_char_logical"
        }
    else:  # manual_investigation
        pattern_mapping = {
            "short_char": "short_strings",
            "short_method": "single_methods",
            "single_char_classes": "single_digit_classes", 
            "two_char_classes": "two_digit_classes",
            "three_char_classes": "three_digit_classes"
        }
    
    # Evaluate individual components
    individual_components_passed = 0
    individual_components_total = 0
    
    for component, threshold_value in thresholds.items():
        if component in ["combined_short_rule", "combined_class_rule"]:
            continue  # Handle combined rules separately
        
        pattern_key = pattern_mapping.get(component, component)
        actual_value = patterns.get(pattern_key, 0)
        
        is_met, threshold_desc, actual_desc = evaluate_threshold(threshold_value, actual_value, logical_classes)
        
        results["individual_components"][component] = {
            "threshold": threshold_desc,
            "actual": actual_desc,
            "passed": is_met,
            "enabled": threshold_value != 0
        }
        
        if threshold_value != 0:  # Only count enabled components
            individual_components_total += 1
            if is_met:
                individual_components_passed += 1
    
    # Evaluate combined rules
    combined_rules_passed = 0
    combined_rules_total = 0
    
    # Combined short rule (short_char + short_method)
    if "combined_short_rule" in thresholds and thresholds["combined_short_rule"] != 0:
        combined_short_actual = patterns.get("short_strings", 0) + patterns.get("single_methods", 0)
        is_met, threshold_desc, actual_desc = evaluate_threshold(
            thresholds["combined_short_rule"], combined_short_actual, logical_classes
        )
        
        results["individual_components"]["combined_short_rule"] = {
            "threshold": threshold_desc,
            "actual": actual_desc,
            "passed": is_met,
            "enabled": True,
            "components": f"short_strings({patterns.get('short_strings', 0)}) + single_methods({patterns.get('single_methods', 0)})"
        }
        
        combined_rules_total += 1
        if is_met:
            combined_rules_passed += 1
    
    # Combined class rule (single + two + three char classes)
    if "combined_class_rule" in thresholds and thresholds["combined_class_rule"] != 0:
        if analysis_method == "yara_strict":
            combined_class_actual = (patterns.get("single_classes", 0) + 
                                   patterns.get("two_char_classes", 0) + 
                                   patterns.get("three_char_classes", 0))
        else:
            combined_class_actual = (patterns.get("single_classes", 0) +
                                   patterns.get("two_char_classes", 0) +
                                   patterns.get("three_char_classes", 0))
        
        is_met, threshold_desc, actual_desc = evaluate_threshold(
            thresholds["combined_class_rule"], combined_class_actual, logical_classes
        )
        
        results["individual_components"]["combined_class_rule"] = {
            "threshold": threshold_desc,
            "actual": actual_desc,
            "passed": is_met,
            "enabled": True,
            "components": f"single({patterns.get('single_classes', 0)}) + two({patterns.get('two_char_classes', 0)}) + three({patterns.get('three_char_classes', 0)})"
        }
        
        combined_rules_total += 1
        if is_met:
            combined_rules_passed += 1
    
    # Calculate totals
    results["components_total"] = individual_components_total + combined_rules_total
    results["components_passed"] = individual_components_passed + combined_rules_passed
    
    # Determine if rule should trigger
    # Rule triggers if ANY enabled component/combined rule passes
    any_component_passed = (individual_components_passed > 0 or combined_rules_passed > 0)
    results["should_trigger"] = any_component_passed
    
    if results["should_trigger"]:
        passed_components = []
        if individual_components_passed > 0:
            passed_components.append(f"{individual_components_passed} individual component(s)")
        if combined_rules_passed > 0:
            passed_components.append(f"{combined_rules_passed} combined rule(s)")
        results["trigger_reason"] = f"Passed: {', '.join(passed_components)}"
    else:
        results["trigger_reason"] = "No components passed thresholds"
    
    return results

def load_obfuscation_rules_config(config_path="obfuscation_rules_config.json"):
    """Load obfuscation detection rules from JSON configuration file."""
    try:
        if not os.path.exists(config_path):
            # Create default config if it doesn't exist
            safe_print(f"⚠️ Rules config not found at {config_path}, using built-in defaults")
            return get_default_rules_config()
        
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        safe_print(f"✅ Loaded obfuscation rules config from {config_path}")
        return config
    except Exception as e:
        safe_print(f"❌ Error loading rules config: {e}")
        safe_print("📋 Using built-in default rules")
        return get_default_rules_config()
        
        for analysis_method in analysis_methods:
            # Select appropriate rule
            selected_rule = select_applicable_rule(
                rules_config, modality, analysis_method, logical_classes_for_eval, dex_count, rule_type
            )
            
            if not selected_rule:
                safe_print(f"⚠️ No applicable {rule_type} rule found for {analysis_method}/{modality}")
                rule_evaluation_results[rule_type][analysis_method] = {
                    "rule_applied": False,
                    "error": f"No applicable {rule_type} rule for {analysis_method}/{modality}"
                }
                continue
            
            # Use appropriate pattern data based on analysis method
            pattern_data = yara_patterns_data if analysis_method == "yara_strict" else manual_patterns_data
            logical_classes = yara_approximate_logical_classes if analysis_method == "yara_strict" else manual_patterns['logical_classes']
            
            # Evaluate rule
            evaluation_result = evaluate_rule_against_patterns(
                selected_rule, pattern_data, logical_classes, analysis_method
            )
            
            rule_evaluation_results[rule_type][analysis_method] = evaluation_result
    
    # Display rule evaluation results
    safe_print(f"\n📊 RULE EVALUATION RESULTS:")
    safe_print(f"{'─'*80}")
    
    for rule_type in rule_types:
        safe_print(f"\n🔍 {rule_type.upper()} RULES:")
        safe_print(f"{'─'*40}")
        
        for analysis_method in analysis_methods:
            method_name = "YARA-STRICT" if analysis_method == "yara_strict" else "MANUAL INVESTIGATION"
            result = rule_evaluation_results[rule_type][analysis_method]
            
            if not result.get("rule_applied", False):
                safe_print(f"❌ {method_name}: {result.get('error', 'Rule not applied')}")
                continue
            
            trigger_status = "🔴 TRIGGER" if result["should_trigger"] else "🟢 NO TRIGGER"
            safe_print(f"📋 {method_name}: {trigger_status}")
            safe_print(f"   Rule: {result['rule_description']}")
            safe_print(f"   Components passed: {result['components_passed']}/{result['components_total']}")
            safe_print(f"   Reason: {result['trigger_reason']}")
            
            # Show individual component details
            for component_name, component_result in result["individual_components"].items():
                if component_result["enabled"]:
                    status = "✅" if component_result["passed"] else "❌"
                    safe_print(f"     {status} {component_name}: {component_result['actual']} vs {component_result['threshold']}")
                    if "components" in component_result:
                        safe_print(f"        └─ {component_result['components']}")
    
    # Determine final results based on rule evaluation
    # For compatibility, use minimal rules for primary decision making
    yara_minimal_result = rule_evaluation_results.get("minimal", {}).get("yara_strict", {})
    manual_minimal_result = rule_evaluation_results.get("minimal", {}).get("manual_investigation", {})
    
    # Basic requirements evaluation
    req1_min_classes = total_classes_dex_header >= 50
    req2_logical_classes_yara = yara_approximate_logical_classes > 0
    req2_logical_classes_manual = manual_patterns['logical_classes'] > 0
    
    # Calculate conditions passed based on basic requirements and rule triggers
    conditions_passed = 0
    total_conditions = 7  # 2 basic + up to 5 rule components
    
    if req1_min_classes:
        conditions_passed += 1
    if req2_logical_classes_manual:
        conditions_passed += 1
    
    # Add rule-based conditions passed
    if yara_minimal_result.get("rule_applied", False):
        conditions_passed += yara_minimal_result.get("components_passed", 0)
    
    # Final assessment
    basic_reqs_met_yara = req1_min_classes and req2_logical_classes_yara
    basic_reqs_met_manual = req1_min_classes and req2_logical_classes_manual
    
    # Use rule evaluation results for triggering decisions
    should_trigger_yara = (basic_reqs_met_yara and 
                          yara_minimal_result.get("rule_applied", False) and 
                          yara_minimal_result.get("should_trigger", False))
    
    should_trigger_manual = (basic_reqs_met_manual and 
                            manual_minimal_result.get("rule_applied", False) and 
                            manual_minimal_result.get("should_trigger", False))
    
    percentage = (conditions_passed / total_conditions) * 100
    
    # Prepare method details for backward compatibility
    methods_detail = {
        'configurable_rules': {
            'modality': modality,
            'rule_evaluation_results': rule_evaluation_results,
            'yara_trigger': should_trigger_yara,
            'manual_trigger': should_trigger_manual,
            'basic_requirements_met': {
                'yara': basic_reqs_met_yara,
                'manual': basic_reqs_met_manual
            }
        }
    }
    
    # Calculate methods summary for backward compatibility
    yara_components_passed = yara_minimal_result.get("components_passed", 0) if yara_minimal_result.get("rule_applied") else 0
    manual_components_passed = manual_minimal_result.get("components_passed", 0) if manual_minimal_result.get("rule_applied") else 0
    
    methods_summary = {
        'total_methods': 6,  # Keep for compatibility
        'methods_passed': yara_components_passed,
        'methods_failed': max(0, 6 - yara_components_passed),
        'manual_methods_passed': manual_components_passed,
        'rule_based_evaluation': True,
        'modality': modality
    }
    
    safe_print(f"\n📊 Final Assessment:")
    safe_print(f"   ═══════════════════════════════════════════")
    safe_print(f"   📊 YARA-STRICT Results (Minimal Rule):")
    safe_print(f"   Basic requirements: {'✅ MET' if basic_reqs_met_yara else '❌ NOT MET'}")
    safe_print(f"   Rule components passed: {yara_components_passed}")
    safe_print(f"   Rule should trigger: {'🔴 YES' if should_trigger_yara else '🟢 NO'}")
    
    safe_print(f"\n   📋 MANUAL INVESTIGATION Results (Minimal Rule):")
    safe_print(f"   Basic requirements: {'✅ MET' if basic_reqs_met_manual else '❌ NOT MET'}")
    safe_print(f"   Rule components passed: {manual_components_passed}")
    safe_print(f"   Rule would trigger: {'🔴 YES' if should_trigger_manual else '🟢 NO'}")
    
    safe_print(f"\n   🔍 Effectiveness Gap:")
    gap_components = manual_components_passed - yara_components_passed
    safe_print(f"   Manual finds {gap_components} more passing components than YARA")
    safe_print(f"   Agreement: {'✅ CONSISTENT' if should_trigger_yara == should_trigger_manual else '⚠️ DIFFERENT'}")
    
    safe_print(f"\n   📋 Completion Summary:")
    safe_print(f"   Conditions passed: {conditions_passed}/{total_conditions}")
    safe_print(f"   Completion percentage: {percentage:.1f}%")
    safe_print(f"   DEX modality: {modality}")
    
    # Use manual inspection results for primary return (manual analysis is the focus)
    should_trigger = should_trigger_manual
    
    return percentage, should_trigger, methods_detail, methods_summary

def main():
    parser = argparse.ArgumentParser(description='Comprehensive massive obfuscation rule testing')
    parser.add_argument('input_file', help='APK or DEX file to analyze')
    parser.add_argument('--sdk-config', help='Path to SDK configuration JSON file')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input_file):
        safe_print(f"❌ Error: File not found: {args.input_file}")
        sys.exit(1)
    
    # Load SDK configuration if provided
    sdk_config = None
    if args.sdk_config:
        sdk_config = load_sdk_config_from_file(args.sdk_config)
    
    test_massive_obfuscation_with_percentage(args.input_file, sdk_config)

if __name__ == "__main__":
    main()
