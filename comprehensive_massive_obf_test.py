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

def test_massive_obfuscation_with_percentage(input_file):
    """
    Test massive obfuscation rule and show percentage of conditions met.
    Works with APK or DEX files.
    """
    
    safe_print(f"🔍 Testing massive obfuscation rule on: {input_file}")
    safe_print(f"{'='*80}")
    
    # First, try APKiD scan using command-line interface (same as quick_apk_analyzer)
    try:
        import subprocess
        import json
        
        # Run APKiD using local development version with updated debug rules
        # Use local wrapper that sets up proper environment
        script_dir = os.path.dirname(os.path.abspath(__file__))
        local_apkid = os.path.join(script_dir, 'local_apkid.py')
        
        result = subprocess.run(
            [sys.executable, local_apkid, '--json', input_file],
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
    
    # Analyze each DEX file in detail
    overall_max_percentage = 0
    overall_should_trigger = False
    
    for dex_name, dex_path in dex_files:
        safe_print(f"\n{'='*60}")
        safe_print(f"📊 DETAILED ANALYSIS: {dex_name}")
        safe_print(f"{'='*60}")
        
        try:
            result = analyze_single_dex_detailed(dex_path)
            
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

def analyze_single_dex_detailed(dex_file_path):
    """
    Perform detailed analysis of a single DEX file.
    Returns (percentage, should_trigger).
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
    
    # Main class pattern: /\x00[\x02-\x7F]L[a-zA-Z0-9\$\/_-]+;\x00/ - EXACT YARA regex
    yara_patterns['class_pattern'] = len(re.findall(r'\x00[\x02-\x7F]L[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    
    # SDK exclusion patterns - EXACT YARA regex (synchronized with obfuscators.yara)
    yara_patterns['google_class'] = len(re.findall(r'\x00[\x02-\x7F]Lcom/google/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['com_android_class'] = len(re.findall(r'\x00[\x02-\x7F]Lcom/android/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['android_class'] = len(re.findall(r'\x00[\x02-\x7F]Landroid/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['androidx_class'] = len(re.findall(r'\x00[\x02-\x7F]Landroidx/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['kotlin_class'] = len(re.findall(r'\x00[\x02-\x7F]Lkotlin/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['java_class'] = len(re.findall(r'\x00[\x02-\x7F]Ljava/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['kotlinx_class'] = len(re.findall(r'\x00[\x02-\x7F]Lkotlinx/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['dalvik_class'] = len(re.findall(r'\x00[\x02-\x7F]Ldalvik/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['org_class'] = len(re.findall(r'\x00[\x02-\x7F]Lorg/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    # Additional exclusions synchronized with YARA obfuscators.yara massive_name_obfuscation rule
    yara_patterns['retrofit2_class'] = len(re.findall(r'\x00[\x02-\x7F]Lretrofit2/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['ro_class'] = len(re.findall(r'\x00[\x02-\x7F]Lro/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['view_class'] = len(re.findall(r'\x00[\x02-\x7F]Lview/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['persist_class'] = len(re.findall(r'\x00[\x02-\x7F]Lpersist/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['sun_class'] = len(re.findall(r'\x00[\x02-\x7F]Lsun/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['guava_class'] = len(re.findall(r'\x00[\x02-\x7F]Lguava/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['vnd_android_class'] = len(re.findall(r'\x00[\x02-\x7F]Lvnd/android/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['schemas_android_class'] = len(re.findall(r'\x00[\x02-\x7F]Lschemas/android/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['in_collections_class'] = len(re.findall(r'\x00[\x02-\x7F]Lin/collections/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    yara_patterns['media_class'] = len(re.findall(r'\x00[\x02-\x7F]Lmedia/[a-zA-Z0-9\$\/_-]+;\x00', data_str))
    
    # Legitimate short pattern - EXACT YARA regex
    yara_patterns['legitimate_short'] = len(re.findall(r'L(io|os|ui|vm|db|js|sx|tv|ai|ar|vr|3d|r|app|net|xml|api|gui|jwt|ssl|tls|rsa|aes|des|md5|sha|url|uri|css|dom|xml|sql|tcp|udp|ftp|ssh|git|svn|cvs|yml|pdf|jpg|png|gif|bmp|ico|zip|tar|rar|log|tmp|bin|lib|jar|war|ear|dex|oat|odex|vdex|art)/', data_str))
    
    # =============================
    # METHOD 2: MANUAL INSPECTION patterns (broader, no strict DEX formatting)
    # =============================
    manual_patterns = {}
    
    # Find ALL class patterns (broader than DEX string table format)
    all_classes = re.findall(r'L[a-zA-Z0-9\$_/]+;', data_str)
    unique_classes = list(set(all_classes))
    
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
    
    def is_sdk_class(class_name):
        """Check if class is from SDK."""
        for pattern in sdk_patterns:
            if re.match(pattern, class_name):
                return True
        return False
    
    def is_legitimate_short(class_name):
        """Check if class is legitimate short name."""
        for pattern in legitimate_patterns:
            if re.match(pattern, class_name):
                return True
        return False
    
    # Filter out SDK and legitimate classes for manual analysis
    logical_classes_manual = []
    sdk_classes_manual = []
    legitimate_classes_manual = []
    
    for class_name in unique_classes:
        if is_sdk_class(class_name):
            sdk_classes_manual.append(class_name)
        elif is_legitimate_short(class_name):
            legitimate_classes_manual.append(class_name)
        else:
            logical_classes_manual.append(class_name)
    
    # Manual analysis of logical classes for obfuscation patterns
    manual_two_digit_classes = []
    manual_three_digit_classes = []
    manual_single_digit_classes = []
    manual_short_strings = []
    manual_single_methods = []
    
    for class_name in logical_classes_manual:
        # Remove 'L' prefix and ';' suffix
        clean_name = class_name[1:-1]
        
        # Analyze different patterns
        if '/' in clean_name:
            # Package structure: analyze each part for single characters
            parts = clean_name.split('/')
            
            # Count single character parts (any part that is exactly 1 character)
            single_char_parts = [part for part in parts if len(part) == 1 and part.isalpha()]
            if single_char_parts:
                manual_single_digit_classes.append(class_name)
            
            # Check if it's a two-digit pattern like: ab/cd, xy/zw (EXACTLY 2 parts, each 2 chars)
            if (len(parts) == 2 and 
                len(parts[0]) == 2 and len(parts[1]) == 2 and
                parts[0].isalpha() and parts[1].isalpha()):
                manual_two_digit_classes.append(class_name)
            
            # Check if it's a three-digit pattern like: abc/def, xyz/uvw (EXACTLY 2 parts, each 3 chars)
            elif (len(parts) == 2 and 
                  len(parts[0]) == 3 and len(parts[1]) == 3 and
                  parts[0].isalpha() and parts[1].isalpha()):
                manual_three_digit_classes.append(class_name)
        
        else:
            # No package structure - analyze direct class name
            if len(clean_name) == 2 and clean_name.isalpha():
                manual_two_digit_classes.append(class_name)
            elif len(clean_name) == 3 and clean_name.isalpha():
                manual_three_digit_classes.append(class_name)
            elif len(clean_name) == 1 and clean_name.isalpha():
                manual_single_digit_classes.append(class_name)
    
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
    manual_patterns['single_digit_classes'] = len(manual_single_digit_classes)
    manual_patterns['two_digit_classes'] = len(manual_two_digit_classes)
    
    # Debug output for single class detection - always show when no single classes found
    if len(manual_single_digit_classes) == 0:
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
    
    manual_patterns['three_digit_classes'] = len(manual_three_digit_classes)
    manual_patterns['single_methods'] = len(manual_single_methods)
    manual_patterns['short_strings'] = len(manual_short_strings)
    
    # For backward compatibility, use YARA patterns as primary
    patterns = yara_patterns
    
    # Calculate using EXACT YARA logic - FIXED to match YARA's dex.header.class_defs_size
    total_classes_regex = patterns['class_pattern']  # Keep for comparison
    total_classes_dex_header = dex_header_class_defs_size  # Use DEX header like YARA
    # SDK classes calculation synchronized with YARA obfuscators.yara massive_name_obfuscation rule
    sdk_classes_raw = (patterns['google_class'] + patterns['com_android_class'] + patterns['android_class'] + patterns['androidx_class'] + 
                       patterns['kotlin_class'] + patterns['java_class'] + patterns['kotlinx_class'] + 
                       patterns['dalvik_class'] + patterns['org_class'] + patterns['retrofit2_class'] + 
                       patterns['ro_class'] + patterns['view_class'] + patterns['persist_class'] + 
                       patterns['sun_class'] + patterns['guava_class'] + patterns['vnd_android_class'] + 
                       patterns['schemas_android_class'] + patterns['in_collections_class'] + 
                       patterns['media_class'] + patterns['legitimate_short'])
    
    # CRITICAL FIX: Cap SDK classes to never exceed total classes (prevents negative logical classes)
    # Root cause: YARA patterns count string table occurrences, not unique class definitions
    sdk_classes = min(sdk_classes_raw, total_classes_dex_header)
    
    # YARA uses dex.header.class_defs_size for total classes but regex patterns for SDK classes
    logical_classes = max(0, total_classes_dex_header - sdk_classes)
    
    # Debug logging for the PhotoTable case
    if sdk_classes_raw != sdk_classes:
        safe_print(f"   🔧 FIX APPLIED: SDK classes capped from {sdk_classes_raw:,} to {sdk_classes:,}")
        safe_print(f"   📊 Reason: SDK count exceeded total classes ({total_classes_dex_header:,})")
    
    if logical_classes == 0 and total_classes_dex_header > 0:
        safe_print(f"   ⚠️  WARNING: All {total_classes_dex_header:,} classes detected as SDK classes")
        safe_print(f"   💡 Non-SDK classes (like zebra.util) may be miscategorized as SDK")
    
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
    safe_print(f"   Logical classes: {logical_classes:,}")
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
    req2_logical_classes_yara = logical_classes > 0
    req2_logical_classes_manual = manual_patterns['logical_classes'] > 0
    
    # Use manual requirements for condition counting (since this is manual analysis)
    if req1_min_classes:
        conditions_passed += 1
    if req2_logical_classes_manual:
        conditions_passed += 1
    
    safe_print(f"Requirement 1 - Min classes: {total_classes_dex_header} >= 50 = {'✅' if req1_min_classes else '❌'}")
    safe_print(f"Requirement 2 - YARA logical classes: {logical_classes} > 0 = {'✅' if req2_logical_classes_yara else '❌'}")
    safe_print(f"Requirement 2 - Manual logical classes: {manual_patterns['logical_classes']} > 0 = {'✅' if req2_logical_classes_manual else '❌'}")
    
    if not req2_logical_classes_manual:
        safe_print(f"⚠️  Cannot evaluate manual analysis ratios without logical classes")
        percentage = (conditions_passed / total_conditions) * 100
        safe_print(f"\n🎯 Manual Analysis Completion: {percentage:.1f}% ({conditions_passed}/{total_conditions})")
        return percentage, False
    
    # DUAL METHOD EVALUATIONS
    safe_print(f"\n📊 YARA-STRICT vs MANUAL ANALYSIS Comparison:")
    safe_print(f"{'─'*60}")
    
    # Method evaluations with detailed breakdown - BOTH approaches
    methods_passed_yara = 0
    methods_passed_manual = 0
    
    # Method 1: Short strings ratio - BOTH approaches
    method1_count_ok_yara = short_strings > 20
    method1_ratio_yara = (short_strings * 3 / logical_classes) if logical_classes > 0 else 0
    method1_ratio_ok_yara = method1_ratio_yara > 1.0  # 33.3%
    method1_passed_yara = method1_count_ok_yara and method1_ratio_ok_yara
    
    method1_count_ok_manual = manual_patterns['short_strings'] > 20
    method1_ratio_manual = (manual_patterns['short_strings'] * 3 / manual_patterns['logical_classes']) if manual_patterns['logical_classes'] > 0 else 0
    method1_ratio_ok_manual = method1_ratio_manual > 1.0  # 33.3%
    method1_passed_manual = method1_count_ok_manual and method1_ratio_ok_manual
    
    if method1_passed_yara:
        conditions_passed += 1
        methods_passed_yara += 1
    if method1_passed_manual:
        methods_passed_manual += 1
        
    safe_print(f"Method 1 - Short strings:")
    safe_print(f"   YARA:   {'✅ PASS' if method1_passed_yara else '❌ FAIL'} (count: {short_strings}, ratio: {method1_ratio_yara:.2f})")
    safe_print(f"   MANUAL: {'✅ PASS' if method1_passed_manual else '❌ FAIL'} (count: {manual_patterns['short_strings']}, ratio: {method1_ratio_manual:.2f})")
    
    # Method 2: Single class names - BOTH approaches
    method2_count_ok_yara = single_classes > 10
    method2_ratio_yara = (single_classes * 2 / logical_classes) if logical_classes > 0 else 0
    method2_ratio_ok_yara = method2_ratio_yara > 1.0  # 50%
    method2_passed_yara = method2_count_ok_yara and method2_ratio_ok_yara
    
    method2_count_ok_manual = manual_patterns['single_digit_classes'] > 10
    method2_ratio_manual = (manual_patterns['single_digit_classes'] * 2 / manual_patterns['logical_classes']) if manual_patterns['logical_classes'] > 0 else 0
    method2_ratio_ok_manual = method2_ratio_manual > 1.0  # 50%
    method2_passed_manual = method2_count_ok_manual and method2_ratio_ok_manual
    
    if method2_passed_yara:
        conditions_passed += 1
        methods_passed_yara += 1
    if method2_passed_manual:
        methods_passed_manual += 1
        
    safe_print(f"Method 2 - Single classes:")
    safe_print(f"   YARA:   {'✅ PASS' if method2_passed_yara else '❌ FAIL'} (count: {single_classes}, ratio: {method2_ratio_yara:.2f})")
    safe_print(f"   MANUAL: {'✅ PASS' if method2_passed_manual else '❌ FAIL'} (count: {manual_patterns['single_digit_classes']}, ratio: {method2_ratio_manual:.2f})")
    
    # Method 3: Two-char classes - BOTH approaches
    two_char_logical = max(0, two_char_classes - patterns['legitimate_short'])
    method3_count_ok_yara = two_char_logical > 15
    method3_ratio_yara = (two_char_logical * 2 / logical_classes) if logical_classes > 0 else 0
    method3_ratio_ok_yara = method3_ratio_yara > 1.0  # 50%
    method3_passed_yara = method3_count_ok_yara and method3_ratio_ok_yara
    
    method3_count_ok_manual = manual_patterns['two_digit_classes'] > 15
    method3_ratio_manual = (manual_patterns['two_digit_classes'] * 2 / manual_patterns['logical_classes']) if manual_patterns['logical_classes'] > 0 else 0
    method3_ratio_ok_manual = method3_ratio_manual > 1.0  # 50%
    method3_passed_manual = method3_count_ok_manual and method3_ratio_ok_manual
    
    if method3_passed_yara:
        conditions_passed += 1
        methods_passed_yara += 1
    if method3_passed_manual:
        methods_passed_manual += 1
        
    safe_print(f"Method 3 - Two-char classes:")
    safe_print(f"   YARA:   {'✅ PASS' if method3_passed_yara else '❌ FAIL'} (count: {two_char_logical}, ratio: {method3_ratio_yara:.2f})")
    safe_print(f"   MANUAL: {'✅ PASS' if method3_passed_manual else '❌ FAIL'} (count: {manual_patterns['two_digit_classes']}, ratio: {method3_ratio_manual:.2f})")
    
    # Method 3b: Three-char classes - BOTH approaches
    three_char_logical = max(0, three_char_classes - patterns['legitimate_short'])
    method3b_count_ok_yara = three_char_logical > 15
    method3b_ratio_yara = (three_char_logical * 3 / logical_classes) if logical_classes > 0 else 0
    method3b_ratio_ok_yara = method3b_ratio_yara > 1.0  # 33.3%
    method3b_passed_yara = method3b_count_ok_yara and method3b_ratio_ok_yara
    
    method3b_count_ok_manual = manual_patterns['three_digit_classes'] > 15
    method3b_ratio_manual = (manual_patterns['three_digit_classes'] * 3 / manual_patterns['logical_classes']) if manual_patterns['logical_classes'] > 0 else 0
    method3b_ratio_ok_manual = method3b_ratio_manual > 1.0  # 33.3%
    method3b_passed_manual = method3b_count_ok_manual and method3b_ratio_ok_manual
    
    if method3b_passed_yara:
        conditions_passed += 1
        methods_passed_yara += 1
    if method3b_passed_manual:
        methods_passed_manual += 1
        
    safe_print(f"Method 3b - Three-char classes:")
    safe_print(f"   YARA:   {'✅ PASS' if method3b_passed_yara else '❌ FAIL'} (count: {three_char_logical}, ratio: {method3b_ratio_yara:.2f})")
    safe_print(f"   MANUAL: {'✅ PASS' if method3b_passed_manual else '❌ FAIL'} (count: {manual_patterns['three_digit_classes']}, ratio: {method3b_ratio_manual:.2f})")
    
    # Method 4: Single methods - BOTH approaches
    method4_count_ok_yara = single_methods > 30
    method4_ratio_yara = (single_methods * 4 / logical_classes) if logical_classes > 0 else 0
    method4_ratio_ok_yara = method4_ratio_yara > 1.0  # 25%
    method4_passed_yara = method4_count_ok_yara and method4_ratio_ok_yara
    
    method4_count_ok_manual = manual_patterns['single_methods'] > 30
    method4_ratio_manual = (manual_patterns['single_methods'] * 4 / manual_patterns['logical_classes']) if manual_patterns['logical_classes'] > 0 else 0
    method4_ratio_ok_manual = method4_ratio_manual > 1.0  # 25%
    method4_passed_manual = method4_count_ok_manual and method4_ratio_ok_manual
    
    if method4_passed_yara:
        conditions_passed += 1
        methods_passed_yara += 1
    if method4_passed_manual:
        methods_passed_manual += 1
        
    safe_print(f"Method 4 - Single methods:")
    safe_print(f"   YARA:   {'✅ PASS' if method4_passed_yara else '❌ FAIL'} (count: {single_methods}, ratio: {method4_ratio_yara:.2f})")
    safe_print(f"   MANUAL: {'✅ PASS' if method4_passed_manual else '❌ FAIL'} (count: {manual_patterns['single_methods']}, ratio: {method4_ratio_manual:.2f})")
    
    # Method 5: Combined extreme - BOTH approaches
    combined_obf_yara = short_strings + single_classes + two_char_logical + three_char_logical
    method5_classes_ok_yara = logical_classes > 50
    method5_ratio_yara = (combined_obf_yara / logical_classes) if logical_classes > 0 else 0
    method5_ratio_ok_yara = method5_ratio_yara > 0.6  # 60%
    method5_passed_yara = method5_classes_ok_yara and method5_ratio_ok_yara
    
    combined_obf_manual = (manual_patterns['short_strings'] + manual_patterns['single_digit_classes'] + 
                          manual_patterns['two_digit_classes'] + manual_patterns['three_digit_classes'])
    method5_classes_ok_manual = manual_patterns['logical_classes'] > 50
    method5_ratio_manual = (combined_obf_manual / manual_patterns['logical_classes']) if manual_patterns['logical_classes'] > 0 else 0
    method5_ratio_ok_manual = method5_ratio_manual > 0.6  # 60%
    method5_passed_manual = method5_classes_ok_manual and method5_ratio_ok_manual
    
    safe_print(f"Method 5 - Combined extreme:")
    safe_print(f"   YARA:   {'✅ PASS' if method5_passed_yara else '❌ FAIL'} (combined: {combined_obf_yara}, ratio: {method5_ratio_yara:.2f})")
    safe_print(f"   MANUAL: {'✅ PASS' if method5_passed_manual else '❌ FAIL'} (combined: {combined_obf_manual}, ratio: {method5_ratio_manual:.2f})")
    
    # Final assessment - BOTH approaches with method-specific requirements
    # YARA-strict requirements
    basic_reqs_met_yara = req1_min_classes and req2_logical_classes_yara
    any_method_passed_yara = methods_passed_yara > 0 or method5_passed_yara
    should_trigger_yara = basic_reqs_met_yara and any_method_passed_yara
    
    # Manual inspection requirements (uses manual logical classes)
    basic_reqs_met_manual = req1_min_classes and req2_logical_classes_manual
    any_method_passed_manual = methods_passed_manual > 0 or method5_passed_manual
    should_trigger_manual = basic_reqs_met_manual and any_method_passed_manual
    
    percentage = (conditions_passed / total_conditions) * 100
    
    
    # Prepare detailed method information for structured output (using YARA values for compatibility)
    methods_detail = {
        'method_1_short_strings': {
            'passed': method1_passed_yara,
            'count_threshold': 20,
            'count_actual': short_strings,
            'count_ok': method1_count_ok_yara,
            'ratio_threshold': 1.0,
            'ratio_actual': method1_ratio_yara,
            'ratio_ok': method1_ratio_ok_yara,
            'description': 'Short strings (a-e) ratio 33.3%',
            'manual_passed': method1_passed_manual,
            'manual_count': manual_patterns['short_strings'],
            'manual_ratio': method1_ratio_manual
        },
        'method_2_single_classes': {
            'passed': method2_passed_yara,
            'count_threshold': 10,
            'count_actual': single_classes,
            'count_ok': method2_count_ok_yara,
            'ratio_threshold': 1.0,
            'ratio_actual': method2_ratio_yara,
            'ratio_ok': method2_ratio_ok_yara,
            'description': 'Single class names ratio 50%',
            'manual_passed': method2_passed_manual,
            'manual_count': manual_patterns['single_digit_classes'],
            'manual_ratio': method2_ratio_manual
        },
        'method_3_two_char_classes': {
            'passed': method3_passed_yara,
            'count_threshold': 15,
            'count_actual': two_char_logical,
            'count_ok': method3_count_ok_yara,
            'ratio_threshold': 1.0,
            'ratio_actual': method3_ratio_yara,
            'ratio_ok': method3_ratio_ok_yara,
            'description': 'Two-char classes (logical) ratio 50%',
            'manual_passed': method3_passed_manual,
            'manual_count': manual_patterns['two_digit_classes'],
            'manual_ratio': method3_ratio_manual
        },
        'method_3b_three_char_classes': {
            'passed': method3b_passed_yara,
            'count_threshold': 15,
            'count_actual': three_char_logical,
            'count_ok': method3b_count_ok_yara,
            'ratio_threshold': 1.0,
            'ratio_actual': method3b_ratio_yara,
            'ratio_ok': method3b_ratio_ok_yara,
            'description': 'Three-char classes (logical) ratio 33.3%',
            'manual_passed': method3b_passed_manual,
            'manual_count': manual_patterns['three_digit_classes'],
            'manual_ratio': method3b_ratio_manual
        },
        'method_4_single_methods': {
            'passed': method4_passed_yara,
            'count_threshold': 30,
            'count_actual': single_methods,
            'count_ok': method4_count_ok_yara,
            'ratio_threshold': 1.0,
            'ratio_actual': method4_ratio_yara,
            'ratio_ok': method4_ratio_ok_yara,
            'description': 'Single methods ratio 25%',
            'manual_passed': method4_passed_manual,
            'manual_count': manual_patterns['single_methods'],
            'manual_ratio': method4_ratio_manual
        },
        'method_5_combined_extreme': {
            'passed': method5_passed_yara,
            'count_threshold': 50,
            'count_actual': logical_classes,
            'count_ok': method5_classes_ok_yara,
            'ratio_threshold': 0.6,
            'ratio_actual': method5_ratio_yara,
            'ratio_ok': method5_ratio_ok_yara,
            'description': 'Combined extreme obfuscation 60%',
            'manual_passed': method5_passed_manual,
            'manual_count': combined_obf_manual,
            'manual_ratio': method5_ratio_manual
        }
    }
    
    # Calculate methods passed/failed summary (using YARA for primary reporting)
    methods_summary = {
        'total_methods': 6,
        'methods_passed': methods_passed_yara + (1 if method5_passed_yara else 0),
        'methods_failed': 6 - (methods_passed_yara + (1 if method5_passed_yara else 0)),
        'primary_methods_passed': methods_passed_yara,  # Methods 1-4
        'alternative_method_passed': method5_passed_yara,  # Method 5
        'manual_methods_passed': methods_passed_manual + (1 if method5_passed_manual else 0),
        'manual_primary_methods_passed': methods_passed_manual
    }
    
    safe_print(f"\n📊 Final Assessment:")
    safe_print(f"   ═══════════════════════════════════════════")
    safe_print(f"   📊 YARA-STRICT Results (Primary):")
    safe_print(f"   Basic requirements: {'✅ MET' if basic_reqs_met_yara else '❌ NOT MET'}")
    safe_print(f"   Methods passed: {methods_passed_yara}/4 (+ Method 5: {'✅' if method5_passed_yara else '❌'})")
    safe_print(f"   Any detection method passed: {'✅' if any_method_passed_yara else '❌'}")
    safe_print(f"   Conditions passed: {conditions_passed}/{total_conditions}")
    safe_print(f"   Completion percentage: {percentage:.1f}%")
    safe_print(f"   Rule should trigger: {'🔴 YES' if should_trigger_yara else '🟢 NO'}")
    
    safe_print(f"\n   📋 MANUAL INSPECTION Results (Comparison):")
    safe_print(f"   Methods passed: {methods_passed_manual}/4 (+ Method 5: {'✅' if method5_passed_manual else '❌'})")
    safe_print(f"   Any detection method passed: {'✅' if any_method_passed_manual else '❌'}")
    safe_print(f"   Rule would trigger: {'🔴 YES' if should_trigger_manual else '🟢 NO'}")
    
    safe_print(f"\n   🔍 Effectiveness Gap:")
    gap_methods = methods_passed_manual - methods_passed_yara
    safe_print(f"   Manual finds {gap_methods} more detection methods than YARA")
    safe_print(f"   Agreement: {'✅ CONSISTENT' if should_trigger_yara == should_trigger_manual else '⚠️ DIFFERENT'}")
    
    # Use manual inspection results for primary return (manual analysis is the focus)
    should_trigger = should_trigger_manual
    
    return percentage, should_trigger, methods_detail, methods_summary

def main():
    if len(sys.argv) != 2:
        safe_print("Usage: python comprehensive_massive_obf_test.py <file_path>")
        safe_print("Supports: APK files, DEX files")
        safe_print("Example: python comprehensive_massive_obf_test.py app.apk")
        safe_print("Example: python comprehensive_massive_obf_test.py classes.dex")
        sys.exit(1)
    
    input_file = sys.argv[1]
    if not os.path.exists(input_file):
        safe_print(f"❌ Error: File not found: {input_file}")
        sys.exit(1)
    
    test_massive_obfuscation_with_percentage(input_file)

if __name__ == "__main__":
    main()
