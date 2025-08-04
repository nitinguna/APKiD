#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zebra SDK Discovery Script

Recursively scans folders for APK files with com.zebra or com.symbol package names,
extracts DEX files, analyzes logical classes, and identifies undiscovered SDK classes.

This script generates a JSON configuration file with newly discovered SDK class patterns
that can be used with the APKiD SDK configuration system.
"""

import os
import sys
import json
import tempfile
import zipfile
import subprocess
import argparse
import re
from pathlib import Path
import struct
import signal
import threading
import time
from collections import defaultdict, Counter

# Set up proper encoding for Windows
if sys.platform == "win32":
    import codecs
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    else:
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach(), errors='replace')

def safe_print(*args, **kwargs):
    """Safe print function that handles unicode encoding issues."""
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        safe_args = []
        for arg in args:
            if isinstance(arg, str):
                safe_args.append(arg.encode('ascii', errors='replace').decode('ascii'))
            else:
                safe_args.append(str(arg).encode('ascii', errors='replace').decode('ascii'))
        print(*safe_args, **kwargs)

def extract_package_name(apk_path):
    """Extract package name from APK using aapt or zipfile parsing"""
    try:
        # Try using aapt first (most reliable)
        try:
            result = subprocess.run(
                ['aapt', 'dump', 'badging', apk_path],
                capture_output=True,
                text=True,
                timeout=30,
                errors='replace'  # Handle encoding issues
            )
            if result.returncode == 0 and result.stdout:
                # Fix: Check if stdout is not None before calling split
                stdout_lines = result.stdout.split('\n') if result.stdout else []
                for line in stdout_lines:
                    if line.startswith('package: name='):
                        # Extract package name from: package: name='com.example.app' versionCode='1'
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
                # Look for package name patterns in the binary manifest
                for pattern in [rb'[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*){2,}']:
                    matches = re.findall(pattern, manifest_data)
                    for match in matches:
                        try:
                            candidate = match.decode('utf-8', errors='ignore')
                            if (len(candidate) > 5 and 
                                not candidate.startswith(('android.', 'java.', 'javax.')) and
                                candidate.count('.') >= 2):
                                return candidate
                        except (UnicodeDecodeError, AttributeError):
                            continue
        except (zipfile.BadZipFile, zipfile.LargeZipFile, KeyError, OSError):
            # Handle corrupted or invalid APK files
            pass
        
        return None
        
    except Exception as e:
        safe_print(f"    Warning: Could not extract package name from {os.path.basename(apk_path)}: {e}")
        return None

def is_zebra_package(package_name):
    """Check if package name starts with com.zebra or com.symbol"""
    if not package_name:
        return False
    return package_name.startswith('com.zebra') or package_name.startswith('com.symbol')

def extract_dex_files(apk_path, temp_dir):
    """Extract all DEX files from APK"""
    dex_files = []
    try:
        with zipfile.ZipFile(apk_path, 'r') as apk_zip:
            for file_info in apk_zip.filelist:
                if file_info.filename.endswith('.dex'):
                    try:
                        dex_path = os.path.join(temp_dir, os.path.basename(file_info.filename))
                        # Ensure safe filename
                        if not os.path.basename(file_info.filename):
                            continue
                            
                        with open(dex_path, 'wb') as dex_file:
                            dex_data = apk_zip.read(file_info.filename)
                            if len(dex_data) < 100:  # Skip very small DEX files (likely corrupted)
                                safe_print(f"    Skipping tiny DEX file: {file_info.filename} ({len(dex_data)} bytes)")
                                continue
                            dex_file.write(dex_data)
                        dex_files.append(dex_path)
                        safe_print(f"    Extracted: {file_info.filename} ({file_info.file_size:,} bytes)")
                    except (OSError, zipfile.BadZipFile, KeyError) as e:
                        safe_print(f"    Error extracting {file_info.filename}: {e}")
                        continue
        return dex_files
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError) as e:
        safe_print(f"    Error extracting DEX files from {os.path.basename(apk_path)}: {e}")
        return []
    except Exception as e:
        safe_print(f"    Unexpected error extracting DEX files: {e}")
        return []

def extract_logical_classes_from_dex(dex_file_path):
    """
    Extract logical classes from DEX file using manual inspection method
    Based on comprehensive_massive_obf_test.py logic
    """
    try:
        # Check if file exists and is readable
        if not os.path.exists(dex_file_path):
            safe_print(f"    Error: DEX file does not exist: {dex_file_path}")
            return []
            
        file_size = os.path.getsize(dex_file_path)
        if file_size < 100:
            safe_print(f"    Skipping very small DEX file: {os.path.basename(dex_file_path)} ({file_size} bytes)")
            return []
            
        with open(dex_file_path, 'rb') as f:
            dex_data = f.read()
            
        # Validate DEX header
        if len(dex_data) < 8 or not dex_data.startswith(b'dex\n'):
            safe_print(f"    Invalid DEX file format: {os.path.basename(dex_file_path)}")
            return []
            
    except (OSError, IOError, PermissionError) as e:
        safe_print(f"    Error reading DEX file {os.path.basename(dex_file_path)}: {e}")
        return []
    except Exception as e:
        safe_print(f"    Unexpected error reading DEX file {os.path.basename(dex_file_path)}: {e}")
        return []
    
    # Convert to latin-1 string for regex operations
    try:
        data_str = dex_data.decode('latin-1')
    except (UnicodeDecodeError, AttributeError):
        try:
            # Fallback: use bytes representation
            data_str = str(dex_data)
        except Exception as e:
            safe_print(f"    Error converting DEX data to string: {e}")
            return []
    
    # Extract all class definitions using DEX string table format
    try:
        # Look for complete class definitions: L<package>/<class>;
        class_pattern = r'L([a-zA-Z0-9_$\./]+);'
        all_classes = re.findall(class_pattern, data_str)
        
        # Convert back to proper DEX format and deduplicate
        unique_classes = set()
        for class_match in all_classes:
            if class_match:  # Ensure non-empty match
                # Fix: Don't add extra 'L' since the pattern already expects it
                full_class = f'L{class_match};'
                unique_classes.add(full_class)
        
        # Also look for malformed multiple-L classes and fix them
        malformed_patterns = [
            r'LL([a-zA-Z0-9_$\./]+);',  # Double L
            r'LLL([a-zA-Z0-9_$\./]+);',  # Triple L
            r'LLLL([a-zA-Z0-9_$\./]+);',  # Quadruple L (extreme cases)
        ]
        
        for malformed_pattern in malformed_patterns:
            malformed_classes = re.findall(malformed_pattern, data_str)
            for class_match in malformed_classes:
                if class_match and '/' in class_match:  # Ensure valid structure
                    # Fix malformed classes by removing extra Ls
                    corrected_class = f'L{class_match};'
                    unique_classes.add(corrected_class)
        
        safe_print(f"    Found {len(unique_classes):,} unique classes in {os.path.basename(dex_file_path)}")
        
    except (re.error, MemoryError) as e:
        safe_print(f"    Error processing DEX classes: {e}")
        return []
    except Exception as e:
        safe_print(f"    Unexpected error processing DEX classes: {e}")
        return []
    
    # Filter for logical classes (exclude SDK patterns)
    sdk_patterns = [
        # Google/Android SDK patterns
        r'^Lcom/google/',
        r'^Lcom/android/',
        r'^Landroid/',
        r'^Landroidx/',
        
        # Java/Kotlin SDK patterns
        r'^Lkotlin/',
        r'^Ljava/',
        r'^Lkotlinx/',
        r'^Ljavax/',
        r'^Lsun/',
        
        # Android system patterns
        r'^Ldalvik/',
        r'^Lvnd/android/',
        r'^Lschemas/android/',
        
        # Common library patterns
        r'^Lorg/',
        r'^Lretrofit2/',
        r'^Lro/',
        r'^Lview/',
        r'^Lpersist/',
        r'^Lguava/',
        r'^Lin/collections/',
        r'^Lmedia/',
        
        # Additional common SDK patterns
        r'^Lcom/facebook/',
        r'^Lcom/twitter/',
        r'^Lcom/instagram/',
        r'^Lcom/linkedin/',
        r'^Lcom/microsoft/',
        r'^Lcom/amazonaws/',
        r'^Lcom/squareup/',
        r'^Lcom/github/',
        r'^Lcom/firebase/',
        r'^Lcom/crashlytics/',
        r'^Lcom/flurry/',
        r'^Lcom/unity3d/',
        r'^Lcom/adobe/',
        r'^Lcom/paypal/',
        r'^Lcom/spotify/',
        r'^Lcom/dropbox/',
        
        # Framework patterns
        r'^Lnet/sf/',
        r'^Lorg/apache/',
        r'^Lorg/json/',
        r'^Lorg/xml/',
        r'^Lorg/w3c/',
        r'^Lorg/eclipse/',
        r'^Lorg/jetbrains/',
        
        # Build tools and support
        r'^Lcom/intellij/',
        r'^Lcom/jetbrains/',
        r'^Lcom/gradle/',
        r'^Lcom/android/tools/',
        
        # Testing frameworks
        r'^Ljunit/',
        r'^Lorg/junit/',
        r'^Lorg/mockito/',
        r'^Lorg/hamcrest/',
        
        # Common utilities
        r'^Lcom/sun/',
        r'^Ljavassist/',
        r'^Lorg/slf4j/',
        r'^Lch/qos/logback/',
        r'^Lorg/apache/log4j/',
    ]
    
    # Legitimate short patterns (not obfuscated)
    legitimate_patterns = [
        r'^L(io|os|ui|vm|db|js|sx|tv|ai|ar|vr|3d|r|app|net|xml|api|gui)/',
        r'^L(jwt|ssl|tls|rsa|aes|des|md5|sha|url|uri|css|dom|sql)/',
        r'^L(tcp|udp|ftp|ssh|git|svn|cvs|yml|pdf|jpg|png|gif|bmp)/',
        r'^L(ico|zip|tar|rar|log|tmp|bin|lib|jar|war|ear|dex)/',
        r'^L(oat|odex|vdex|art)/',
        # Additional legitimate short patterns
        r'^L(www|ftp|cdn|aws|gcp|api|sdk|ide|jvm|jre|jdk)/',
        r'^L(gcc|msvc|clang|llvm|npm|pip|git|svn|hg)/',
        r'^L(exe|dll|so|dylib|a|o|obj|lib|ar)/',
        r'^L(png|jpg|jpeg|gif|bmp|svg|ico|webp)/',
        r'^L(mp3|mp4|avi|mov|wav|ogg|flac|m4a)/',
        r'^L(zip|rar|tar|gz|bz2|xz|7z|cab)/',
        r'^L(txt|doc|pdf|xls|ppt|csv|json|xml)/',
        r'^L(html|css|js|ts|php|py|rb|go|rs)/',
        r'^L(sql|db|sqlite|mysql|mongo|redis)/',
        r'^L(http|https|smtp|pop3|imap|ftp|ssh)/'
    ]
    
    def is_sdk_class(class_name):
        """Check if class is from standard SDK."""
        if not class_name or not isinstance(class_name, str):
            return False
        
        # Normalize class name - handle malformed classes
        normalized_class = class_name.strip()
        
        # Handle multiple L prefixes (malformed classes)
        while normalized_class.startswith('LL'):
            normalized_class = normalized_class[1:]  # Remove extra L
        
        # Ensure it starts with L and has proper structure
        if not normalized_class.startswith('L') or len(normalized_class) < 3:
            return False
        
        # Ensure it has proper class structure (at least one slash and ends with semicolon)
        if '/' not in normalized_class or not normalized_class.endswith(';'):
            return False
        
        # Check against all SDK patterns
        for pattern in sdk_patterns:
            try:
                if re.match(pattern, normalized_class):
                    return True
            except re.error:
                # Skip malformed patterns
                continue
        
        return False
    
    def is_legitimate_short(class_name):
        """Check if class is legitimate short name."""
        for pattern in legitimate_patterns:
            if re.match(pattern, class_name):
                return True
        return False
    
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
                # Allow some legitimate 1-3 char components
                legitimate_short_components = {
                    'io', 'os', 'ui', 'vm', 'db', 'js', 'tv', 'ai', 'ar', 'vr', '3d',
                    'www', 'ftp', 'cdn', 'aws', 'gcp', 'api', 'sdk', 'ide', 'jvm', 'jre', 'jdk',
                    'gcc', 'npm', 'pip', 'git', 'svn', 'exe', 'dll', 'png', 'jpg', 'gif', 'bmp',
                    'svg', 'ico', 'mp3', 'mp4', 'avi', 'mov', 'wav', 'ogg', 'zip', 'rar', 'tar',
                    'txt', 'doc', 'pdf', 'xls', 'ppt', 'csv', 'xml', 'sql', 'app', 'net', 'gui',
                    'jwt', 'ssl', 'tls', 'rsa', 'aes', 'des', 'md5', 'sha', 'url', 'uri', 'css',
                    'dom', 'tcp', 'udp', 'ssh', 'yml', 'log', 'tmp', 'bin', 'lib', 'jar', 'war',
                    'ear', 'dex', 'oat', 'art', 'com', 'org', 'net', 'edu', 'gov', 'mil'
                }
                
                if part.lower() not in legitimate_short_components:
                    return True
        
        return False
    
    def has_obfuscated_pattern(class_name):
        """Check if class appears to be obfuscated (single letters, numbers, random chars)."""
        if not class_name.startswith('L') or not class_name.endswith(';'):
            return False
        
        class_path = class_name[1:-1]
        parts = class_path.split('/')
        
        # Check for common obfuscation patterns
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
    
    # Filter out standard SDK, legitimate classes, very short classes, and obfuscated classes
    logical_classes = []
    short_classes_filtered = 0
    obfuscated_classes_filtered = 0
    
    for class_name in unique_classes:
        if is_sdk_class(class_name):
            continue
        if is_legitimate_short(class_name):
            continue
        if is_very_short_class(class_name):
            short_classes_filtered += 1
            continue
        if has_obfuscated_pattern(class_name):
            obfuscated_classes_filtered += 1
            continue
        
        logical_classes.append(class_name)
    
    safe_print(f"    Filtered out {short_classes_filtered:,} very short classes")
    safe_print(f"    Filtered out {obfuscated_classes_filtered:,} obfuscated classes")
    safe_print(f"    Logical classes (after enhanced filtering): {len(logical_classes):,}")
    return logical_classes

def filter_zebra_symbol_classes(logical_classes):
    """
    Remove com.zebra and com.symbol classes from logical classes
    Return the non-zebra/symbol classes as potential SDK classes
    """
    zebra_symbol_patterns = [
        r'^Lcom/zebra/',
        r'^Lcom/symbol/',
        r'^Lcom/motorolasolutions/'  # Also include Motorola Solutions (parent company)
    ]
    
    def is_zebra_symbol_class(class_name):
        """Check if class is from Zebra/Symbol packages"""
        # Normalize malformed class names (handle multiple L prefixes like LLcom/zebra/)
        normalized_name = class_name
        if class_name.startswith('L'):
            # Remove extra L prefixes - find the first non-L character or valid package start
            i = 0
            while i < len(class_name) and class_name[i] == 'L':
                i += 1
            if i > 1:  # If we found multiple L's
                normalized_name = 'L' + class_name[i:]
        
        for pattern in zebra_symbol_patterns:
            if re.match(pattern, normalized_name):
                return True
        return False
    
    not_discovered_sdk_classes = []
    zebra_symbol_classes = []
    
    for class_name in logical_classes:
        if is_zebra_symbol_class(class_name):
            zebra_symbol_classes.append(class_name)
        else:
            not_discovered_sdk_classes.append(class_name)
    
    safe_print(f"    Zebra/Symbol classes: {len(zebra_symbol_classes):,}")
    safe_print(f"    Not-discovered SDK classes: {len(not_discovered_sdk_classes):,}")
    
    return not_discovered_sdk_classes, zebra_symbol_classes

def analyze_sdk_patterns(sdk_classes, min_classes=3):
    """
    Analyze SDK classes to identify common patterns and group them.
    Enhanced to normalize malformed patterns, deduplicate, and prioritize root-level patterns.
    Returns patterns with their class counts.
    """
    if not sdk_classes:
        return []
    
    # Group classes by package prefix to identify SDK patterns
    package_counter = Counter()
    
    for class_name in sdk_classes:
        # Normalize malformed class names first
        normalized_class = class_name
        if class_name.startswith('L'):
            # Remove extra L prefixes
            i = 0
            while i < len(class_name) and class_name[i] == 'L':
                i += 1
            if i > 1:  # If we found multiple L's
                normalized_class = 'L' + class_name[i:]
        
        # Extract package parts (up to 3 levels deep for SDK identification)
        if normalized_class.startswith('L') and '/' in normalized_class:
            # Convert Lcom/vendor/sdk/Class; to com.vendor.sdk format (removing L prefix)
            class_path = normalized_class[1:].replace('/', '.').rstrip(';')
            parts = class_path.split('.')
            
            # Try different package depth levels
            for depth in range(2, min(len(parts), 5)):  # 2-4 levels deep
                package_prefix = '.'.join(parts[:depth])
                package_counter[package_prefix] += 1
    
    # Find significant package patterns (appearing multiple times)
    candidate_patterns = []
    for package, count in package_counter.most_common():
        if count >= min_classes:  # Use configurable threshold
            candidate_patterns.append((package, count))
    
    # Prioritize root-level patterns: if we have both com.fasterxml and com.fasterxml.jackson,
    # prefer the shorter one if it has sufficient count
    final_patterns = []
    processed_roots = set()
    
    # Sort by package length (shortest first) to prioritize root packages
    candidate_patterns.sort(key=lambda x: len(x[0]))
    
    for package, count in candidate_patterns:
        # Check if this is a sub-package of an already processed root
        is_subpackage = False
        for processed_root in processed_roots:
            if package.startswith(processed_root + '.'):
                is_subpackage = True
                break
        
        if not is_subpackage:
            # Convert to clean format without L prefix: com/vendor/sdk
            clean_pattern = package.replace('.', '/')
            final_patterns.append({
                "pattern": clean_pattern,
                "class_count": count
            })
            processed_roots.add(package)
    
    # If no significant patterns found, return normalized individual classes (up to 50)
    if not final_patterns:
        individual_classes = []
        processed_classes = set()
        
        for class_name in sdk_classes:
            # Normalize malformed class names
            normalized_class = class_name
            if class_name.startswith('L'):
                i = 0
                while i < len(class_name) and class_name[i] == 'L':
                    i += 1
                if i > 1:
                    normalized_class = 'L' + class_name[i:]
            
            # Convert to clean format without L prefix
            if normalized_class.startswith('L') and normalized_class.endswith(';'):
                clean_class = normalized_class[1:-1]  # Remove L and ;
                if clean_class not in processed_classes:
                    individual_classes.append({
                        "pattern": clean_class,
                        "class_count": 1  # Individual classes have count of 1
                    })
                    processed_classes.add(clean_class)
                    
                if len(individual_classes) >= 50:
                    break
        
        safe_print(f"    No significant patterns found, returning {len(individual_classes)} individual classes")
        return individual_classes
    
    safe_print(f"    Identified {len(final_patterns)} root-level SDK patterns (min_classes={min_classes})")
    return final_patterns

def scan_folder_for_zebra_apks(folder_path):
    """Recursively scan folder for APK files with Zebra/Symbol package names"""
    safe_print(f"🔍 Scanning folder: {folder_path}")
    
    zebra_apks = []
    total_apks = 0
    
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.lower().endswith('.apk'):
                total_apks += 1
                apk_path = os.path.join(root, file)
                
                safe_print(f"\n📱 Checking APK: {file}")
                package_name = extract_package_name(apk_path)
                
                if package_name:
                    safe_print(f"   Package: {package_name}")
                    if is_zebra_package(package_name):
                        safe_print(f"   ✅ Zebra/Symbol package detected!")
                        zebra_apks.append((apk_path, package_name))
                    else:
                        safe_print(f"   ❌ Not a Zebra/Symbol package")
                else:
                    safe_print(f"   ⚠️  Could not determine package name")
    
    safe_print(f"\n📊 Scan Summary:")
    safe_print(f"   Total APKs found: {total_apks}")
    safe_print(f"   Zebra/Symbol APKs: {len(zebra_apks)}")
    
    return zebra_apks

def analyze_apk_for_sdk_classes(apk_path, package_name, min_classes=3):
    """Analyze a single APK to extract undiscovered SDK classes"""
    safe_print(f"\n🔬 Analyzing APK: {os.path.basename(apk_path)}")
    safe_print(f"   Package: {package_name}")
    
    all_logical_classes = []
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Extract DEX files
        dex_files = extract_dex_files(apk_path, temp_dir)
        
        if not dex_files:
            safe_print(f"   ❌ No DEX files found")
            return [], 0, 0  # Return empty patterns and zero counts
        
        # Analyze each DEX file
        for dex_file in dex_files:
            safe_print(f"\n   📊 Analyzing {os.path.basename(dex_file)}")
            logical_classes = extract_logical_classes_from_dex(dex_file)
            all_logical_classes.extend(logical_classes)
    
    # Remove duplicates
    unique_logical_classes = list(set(all_logical_classes))
    safe_print(f"\n   📈 Total unique logical classes: {len(unique_logical_classes):,}")
    
    # Filter out Zebra/Symbol classes to find SDK classes
    not_discovered_sdk_classes, zebra_classes = filter_zebra_symbol_classes(unique_logical_classes)
    
    # Analyze and group SDK patterns with configurable threshold
    sdk_patterns = analyze_sdk_patterns(not_discovered_sdk_classes, min_classes)
    
    safe_print(f"   🎯 Final SDK patterns identified: {len(sdk_patterns)}")
    
    # Return patterns along with debug counts
    return sdk_patterns, len(unique_logical_classes), len(not_discovered_sdk_classes)

def generate_sdk_config(results):
    """Generate SDK configuration JSON from analysis results"""
    config = {
        "packages": {},
        "debug_info": {
            "total_packages_analyzed": len(results),
            "total_sdk_patterns": sum(len(data["sdk_patterns"]) for data in results.values()),
            "analysis_timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        }
    }
    
    for package_name, data in results.items():
        if data["sdk_patterns"]:
            # Extract patterns and counts for clean JSON format
            sdk_classes_list = []
            for pattern_data in data["sdk_patterns"]:
                sdk_classes_list.append({
                    "pattern": pattern_data["pattern"],
                    "class_count": pattern_data["class_count"]
                })
            
            config["packages"][package_name] = {
                "sdk_classes": sdk_classes_list,
                "debug": {
                    "total_logical_classes": data["logical_classes_count"],
                    "non_discovered_sdk_classes": data["non_discovered_sdk_count"],
                    "sdk_patterns_found": len(data["sdk_patterns"])
                }
            }
    
    return config

def main():
    parser = argparse.ArgumentParser(
        description='Discover undiscovered SDK classes in Zebra/Symbol APKs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python zebra_sdk_discovery.py /path/to/apks
  python zebra_sdk_discovery.py /path/to/apks --output zebra_sdk_config.json
  python zebra_sdk_discovery.py /path/to/apks --min-classes 5 --max-patterns 20
        """
    )
    
    parser.add_argument('folder', help='Folder to scan recursively for APK files')
    parser.add_argument('--output', default='discovered_zebra_sdk_config.json', 
                       help='Output JSON configuration file (default: discovered_zebra_sdk_config.json)')
    parser.add_argument('--min-classes', type=int, default=3,
                       help='Minimum classes required to identify a SDK pattern (default: 3)')
    parser.add_argument('--max-patterns', type=int, default=50,
                       help='Maximum SDK patterns per package (default: 50)')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose output with detailed class lists')
    
    args = parser.parse_args()
    
    # Validate inputs
    if not os.path.isdir(args.folder):
        safe_print(f"❌ Error: Folder '{args.folder}' does not exist.")
        return 1
    
    safe_print("🚀 Zebra SDK Discovery Tool")
    safe_print("=" * 50)
    
    # Step 1: Scan for Zebra/Symbol APKs
    zebra_apks = scan_folder_for_zebra_apks(args.folder)
    
    if not zebra_apks:
        safe_print("\n❌ No Zebra/Symbol APKs found in the specified folder.")
        return 1
    
    # Step 2: Analyze each APK
    results = {}
    
    for apk_path, package_name in zebra_apks:
        try:
            sdk_classes, logical_count, non_discovered_count = analyze_apk_for_sdk_classes(apk_path, package_name, args.min_classes)
            
            # Limit patterns per package
            if len(sdk_classes) > args.max_patterns:
                sdk_classes = sdk_classes[:args.max_patterns]
                safe_print(f"   ⚠️  Limited to {args.max_patterns} patterns")
            
            if sdk_classes:
                results[package_name] = {
                    "sdk_patterns": sdk_classes,
                    "logical_classes_count": logical_count,
                    "non_discovered_sdk_count": non_discovered_count
                }
                safe_print(f"   ✅ Added {len(sdk_classes)} SDK patterns for {package_name}")
                safe_print(f"   📊 Debug: {logical_count:,} total logical classes, {non_discovered_count:,} non-discovered SDK classes")
                
                # Show pattern details with class counts
                for pattern_data in sdk_classes[:5]:  # Show first 5 patterns with counts
                    safe_print(f"      • {pattern_data['pattern']} ({pattern_data['class_count']} classes)")
                if len(sdk_classes) > 5:
                    safe_print(f"      ... and {len(sdk_classes) - 5} more patterns")
            else:
                safe_print(f"   ⚠️  No significant SDK patterns found for {package_name}")
                safe_print(f"   📊 Debug: {logical_count:,} total logical classes, {non_discovered_count:,} non-discovered SDK classes")
                
        except Exception as e:
            safe_print(f"   ❌ Error analyzing {package_name}: {e}")
            continue
    
    # Step 3: Generate configuration
    if results:
        config = generate_sdk_config(results)
        
        # Save to file
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            
            safe_print(f"\n✅ SDK configuration saved to: {args.output}")
            safe_print(f"\n📊 Final Results:")
            safe_print(f"   Total packages analyzed: {len(results)}")
            
            total_patterns = sum(len(data["sdk_patterns"]) for data in results.values())
            safe_print(f"   Total SDK patterns discovered: {total_patterns}")
            
            # Show summary for each package
            for package_name, data in results.items():
                patterns = data["sdk_patterns"]
                logical_count = data["logical_classes_count"]
                non_discovered_count = data["non_discovered_sdk_count"]
                
                safe_print(f"   📦 {package_name}: {len(patterns)} patterns")
                safe_print(f"      📊 {logical_count:,} logical classes, {non_discovered_count:,} non-discovered SDK classes")
                
                if args.verbose:
                    for pattern_data in patterns[:10]:  # Show first 10 patterns with counts
                        safe_print(f"      • {pattern_data['pattern']} ({pattern_data['class_count']} classes)")
                    if len(patterns) > 10:
                        safe_print(f"      ... and {len(patterns) - 10} more")
            
            safe_print(f"\n💡 Usage: Use this configuration with:")
            safe_print(f"   python quick_apk_analyzer.py /path/to/apks --sdk-config {args.output} --comprehensive")
            
        except Exception as e:
            safe_print(f"❌ Error saving configuration: {e}")
            return 1
    else:
        safe_print("\n⚠️  No SDK patterns discovered in any APKs.")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
