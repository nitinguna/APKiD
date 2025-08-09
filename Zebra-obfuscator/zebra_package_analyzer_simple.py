#!/usr/bin/env python3
"""
Zebra Package Analyzer - Simplified Version (No AAPT dependency)

This script recursively searches for APK files in a given directory,
analyzes their DEX files to detect Zebra/Symbol applications,
and extracts common package usage patterns.

Usage:
    python zebra_package_analyzer_simple.py <directory_path> [--output results/report.json] [--verbose]

Features:
    - No external dependencies (aapt not required)
    - DEX-based package detection for Zebra/Symbol apps
    - Multi-DEX file analysis
    - Package deduplication within APKs
    - Comprehensive usage statistics
    - JSON and human-readable reports
"""

import os
import sys
import re
import json
import zipfile
import tempfile
import shutil
import argparse
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path

class ZebraPackageAnalyzerSimple:
    """Analyzer class for processing APK files and identifying Zebra/Symbol applications"""
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.apk_count = 0
        self.processed_apks = []
        self.failed_apks = []
        self.package_usage = defaultdict(set)  # package -> set of APK names
        self.apk_packages = defaultdict(set)   # APK name -> set of packages
        self.global_package_stats = Counter()
        
        # Package filtering patterns (include APKs with these patterns)
        self.target_package_patterns = [
            r'^com\.zebra\.',
            r'^com\.symbol\.'
        ]
        
        # Package patterns to ignore (too short or system packages)
        self.ignore_patterns = [
            r'^[a-z]$',                    # Single character
            r'^[a-z]{2}$',                 # Two characters
            # Very short package patterns that are likely obfuscated/invalid (including numbers)
            r'^[a-z0-9]\.[a-z0-9]$',             # [x].[x] pattern (with numbers)
            r'^[a-z0-9]\.[a-z0-9]{2}$',          # [x].[xx] pattern (with numbers)
            r'^[a-z0-9]\.[a-z0-9]{3}$',          # [x].[xxx] pattern (with numbers)
            r'^[a-z0-9]{2}\.[a-z0-9]$',          # [xx].[x] pattern (with numbers)
            r'^[a-z0-9]{2}\.[a-z0-9]{2}$',       # [xx].[xx] pattern (with numbers)
            r'^[a-z0-9]{2}\.[a-z0-9]{3}$',       # [xx].[xxx] pattern (with numbers)
            # Additional patterns for very short packages
            r'^[a-z0-9]{1,2}\.[a-z0-9]{1,3}$',   # General short pattern: 1-2 chars . 1-3 chars
            r'^[a-z0-9]{1,3}\.[a-z0-9]{1,2}$',   # General short pattern: 1-3 chars . 1-2 chars
            r'^com\.android\.',            # Android system
            r'^android\.',                 # Android framework
            r'^androidx\.',                # AndroidX
            r'^java\.',                    # Java standard
            r'^javax\.',                   # Java extensions
            r'^kotlin\.',                  # Kotlin
            r'^kotlinx\.',                 # Kotlin extensions
            r'^org\.jetbrains\.',          # JetBrains
            r'^dalvik\.',                  # Dalvik VM
        ]
    
    def log(self, message, level="INFO"):
        """Log messages with timestamp"""
        if self.verbose or level in ["ERROR", "WARNING"]:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] {level}: {message}")
    
    def is_target_apk(self, apk_path):
        """Check if APK's main application package is com.zebra.* or com.symbol.*"""
        try:
            # Method 1: Try to use aapt for reliable package name detection
            app_package = self._get_package_via_aapt(apk_path)
            if app_package:
                self.log(f"Found package name via aapt: {app_package}")
                # Check if main app package matches our target patterns
                for pattern in self.target_package_patterns:
                    if re.match(pattern, app_package):
                        self.log(f"Target APK found: {app_package}")
                        return True, app_package
                
                # Not a target package
                self.log(f"Skipping APK with non-target package: {app_package}")
                return False, f"non_target_{app_package}"
            
            # Method 2: Fallback to AndroidManifest.xml parsing
            app_package = self._get_package_from_manifest(apk_path)
            if app_package:
                self.log(f"Found package name via manifest: {app_package}")
                # Check if main app package matches our target patterns
                for pattern in self.target_package_patterns:
                    if re.match(pattern, app_package):
                        self.log(f"Target APK found: {app_package}")
                        return True, app_package
                
                # Not a target package
                self.log(f"Skipping APK with non-target package: {app_package}")
                return False, f"non_target_{app_package}"
            
            # Method 3: Last resort - DEX analysis (but stricter)
            app_package = self._get_package_from_dex_strict(apk_path)
            if app_package:
                self.log(f"Found package name via DEX analysis: {app_package}")
                # Check if main app package matches our target patterns
                for pattern in self.target_package_patterns:
                    if re.match(pattern, app_package):
                        self.log(f"Target APK found: {app_package}")
                        return True, app_package
                
                # Not a target package
                self.log(f"Skipping APK with non-target package: {app_package}")
                return False, f"non_target_{app_package}"
            
            # Could not determine package
            return False, "package_detection_failed"
                
        except Exception as e:
            self.log(f"Error checking APK {apk_path}: {e}", "ERROR")
            return False, f"error: {e}"
    
    def _get_package_via_aapt(self, apk_path):
        """Try to get package name using aapt tool"""
        try:
            import subprocess
            result = subprocess.run(
                ['aapt', 'dump', 'badging', apk_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.split('\n'):
                    if line and line.startswith('package:'):
                        # Extract package name from: package: name='com.example.app'
                        match = re.search(r"name='([^']+)'", line)
                        if match:
                            return match.group(1)
            return None
            
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError, Exception) as e:
            self.log(f"aapt not available or failed: {e}", "WARNING")
            return None
    
    def _get_package_from_manifest(self, apk_path):
        """Extract package name from AndroidManifest.xml"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Try to read AndroidManifest.xml
                if 'AndroidManifest.xml' in apk_zip.namelist():
                    manifest_data = apk_zip.read('AndroidManifest.xml')
                    
                    # Look for package attribute in binary XML
                    # This is a simplified approach - binary XML parsing is complex
                    # Look for common package patterns in the binary data
                    package_patterns = [
                        rb'com\.zebra\.[a-z0-9._]+',
                        rb'com\.symbol\.[a-z0-9._]+',
                        rb'com\.[a-z0-9._]+\.[a-z0-9._]+',  # General com.* pattern
                    ]
                    
                    for pattern in package_patterns:
                        matches = re.findall(pattern, manifest_data)
                        if matches:
                            try:
                                # Convert bytes to string and clean up
                                package = matches[0].decode('utf-8', errors='ignore')
                                # Basic validation
                                if package and '.' in package and len(package.split('.')) >= 2:
                                    return package
                            except Exception as decode_error:
                                self.log(f"Error decoding manifest package: {decode_error}", "WARNING")
                                continue
            return None
            
        except Exception as e:
            self.log(f"Error reading manifest: {e}", "WARNING")
            return None
    
    def _get_package_from_dex_strict(self, apk_path):
        """Strict DEX analysis to find main application package (not dependencies)"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                dex_files = [f for f in apk_zip.filelist if f.filename.endswith('.dex')]
                
                if not dex_files:
                    return None
                
                # Analyze first DEX file (most likely to contain main app classes)
                dex_data = apk_zip.read(dex_files[0].filename)
                
                # Look for APPLICATION class patterns (more indicative of main package)
                app_class_patterns = [
                    rb'L(com/zebra/[a-z0-9/_]+)/[A-Z][a-zA-Z0-9_]+Application;',
                    rb'L(com/symbol/[a-z0-9/_]+)/[A-Z][a-zA-Z0-9_]+Application;',
                    rb'L(com/[a-z0-9/_]+)/[A-Z][a-zA-Z0-9_]+Application;',
                    rb'L(com/zebra/[a-z0-9/_]+)/MainActivity;',
                    rb'L(com/symbol/[a-z0-9/_]+)/MainActivity;',
                    rb'L(com/[a-z0-9/_]+)/MainActivity;',
                ]
                
                # Prioritize zebra/symbol matches
                for pattern in app_class_patterns:
                    matches = re.findall(pattern, dex_data)
                    for match in matches:
                        try:
                            package = match.decode('utf-8', errors='ignore').replace('/', '.')
                            # Check if it's zebra/symbol first
                            if package and (package.startswith('com.zebra') or package.startswith('com.symbol')):
                                return package
                        except Exception:
                            continue
                
                # If no zebra/symbol Application classes found, try broader search
                broader_patterns = [
                    rb'com/symbol/[a-z0-9]+',
                    rb'com/zebra/[a-z0-9]+',
                    rb'com/[a-z0-9]+/[a-z0-9]+',
                ]
                
                for pattern in broader_patterns:
                    matches = re.findall(pattern, dex_data)
                    if matches:
                        try:
                            package = matches[0].decode('utf-8', errors='ignore').replace('/', '.')
                            # Extract just the base package (first 2-3 parts)
                            if package and '.' in package:
                                parts = package.split('.')
                                if len(parts) >= 2:
                                    base_package = f"{parts[0]}.{parts[1]}"
                                    if len(parts) >= 3:
                                        base_package = f"{parts[0]}.{parts[1]}.{parts[2]}"
                                    
                                    # Prioritize zebra/symbol packages
                                    if base_package.startswith('com.zebra') or base_package.startswith('com.symbol'):
                                        return base_package
                        except Exception:
                            continue
                
                # If no specific matches, try the general patterns for non-zebra packages
                for pattern in app_class_patterns[2:]:  # Skip zebra/symbol specific patterns
                    matches = re.findall(pattern, dex_data)
                    for match in matches:
                        try:
                            package = match.decode('utf-8', errors='ignore').replace('/', '.')
                            # Make sure it's not a known SDK/library package
                            if package and not any(sdk in package for sdk in ['android', 'google', 'androidx', 'kotlin', 'java']):
                                return package
                        except Exception:
                            continue
                
                return None
                
        except Exception as e:
            self.log(f"Error in strict DEX analysis: {e}", "WARNING")
            return None
    
    def _extract_app_package_from_dex(self, dex_data):
        """Try to extract the main app package from DEX data"""
        try:
            # Look for various package patterns
            patterns = [
                rb'com\.[a-z0-9.]+',
                rb'com/[a-z0-9/]+',
                rb'org\.[a-z0-9.]+',
                rb'org/[a-z0-9/]+',
                rb'net\.[a-z0-9.]+',
                rb'net/[a-z0-9/]+'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, dex_data)
                if matches:
                    # Take the first match and clean it up
                    match = matches[0].decode('utf-8', errors='ignore')
                    match = match.replace('/', '.')
                    # Extract just the package part (first 3-4 components)
                    parts = match.split('.')
                    if len(parts) >= 3:
                        return f"{parts[0]}.{parts[1]}.{parts[2]}"
            
            return "unknown_package"
            
        except Exception:
            return "extraction_failed"
    
    def extract_packages_from_dex(self, dex_data):
        """Extract package names from DEX file data"""
        packages = set()
        
        try:
            # Method 1: Binary pattern matching for DEX string table
            # Pattern: \x00[length]L[package_path];\x00
            binary_patterns = [
                rb'\x00[\x02-\x7F]L([a-z][a-z0-9/]*(?:\.[a-z][a-z0-9/]*)*);',
                rb'\x00[\x02-\x7F]L([a-z][a-z0-9/]+);'
            ]
            
            for pattern in binary_patterns:
                matches = re.findall(pattern, dex_data, re.IGNORECASE)
                for match in matches:
                    try:
                        package_path = match.decode('utf-8', errors='ignore')
                        package_name = package_path.replace('/', '.')
                        
                        # Extract first two components
                        parts = package_name.split('.')
                        if len(parts) >= 2:
                            short_package = f"{parts[0]}.{parts[1]}"
                            
                            if not self._should_ignore_package(short_package):
                                packages.add(short_package)
                    except:
                        continue
            
            # Method 2: Text pattern matching (for string references)
            try:
                dex_str = dex_data.decode('utf-8', errors='ignore')
                
                # Look for package patterns in text
                text_patterns = [
                    r'"([a-z][a-z0-9]*\.[a-z][a-z0-9]*(?:\.[a-z0-9]+)*)"',  # Quoted packages
                    r'([a-z][a-z0-9]*\.[a-z][a-z0-9]*)\.[a-zA-Z0-9_$]+',    # Package.Class patterns
                ]
                
                for pattern in text_patterns:
                    matches = re.findall(pattern, dex_str, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                        
                        # Extract first two components
                        parts = match.split('.')
                        if len(parts) >= 2:
                            short_package = f"{parts[0]}.{parts[1]}"
                            
                            if not self._should_ignore_package(short_package):
                                packages.add(short_package)
            except:
                pass
            
            # Method 3: Look for import-style patterns
            import_patterns = [
                rb'import ([a-z][a-z0-9]*\.[a-z][a-z0-9]*)',
                rb'L([a-z][a-z0-9]+)/([a-z][a-z0-9]+)/',
            ]
            
            for pattern in import_patterns:
                matches = re.findall(pattern, dex_data, re.IGNORECASE)
                for match in matches:
                    try:
                        if isinstance(match, tuple):
                            if len(match) >= 2:
                                short_package = f"{match[0].decode('utf-8', errors='ignore')}.{match[1].decode('utf-8', errors='ignore')}"
                            else:
                                short_package = match[0].decode('utf-8', errors='ignore')
                        else:
                            short_package = match.decode('utf-8', errors='ignore')
                        
                        if not self._should_ignore_package(short_package):
                            packages.add(short_package)
                    except:
                        continue
            
        except Exception as e:
            self.log(f"Error extracting packages from DEX: {e}", "ERROR")
        
        return packages
    
    def _should_ignore_package(self, package_name):
        """Check if package should be ignored based on patterns"""
        if not package_name or len(package_name) < 4:
            return True
        
        for pattern in self.ignore_patterns:
            if re.match(pattern, package_name):
                return True
        
        # Additional validation
        if not re.match(r'^[a-z][a-z0-9]*\.[a-z][a-z0-9]*$', package_name):
            return True
        
        # Skip very generic packages
        generic_packages = {'com.android', 'java.lang', 'java.util', 'android.app', 'android.os'}
        if package_name in generic_packages:
            return True
        
        return False
    
    def analyze_apk(self, apk_path):
        """Analyze a single APK file for package usage"""
        apk_name = os.path.basename(apk_path)
        self.log(f"Analyzing APK: {apk_name}")
        
        try:
            # Check if this is a target APK (NOT Zebra/Symbol)
            is_target, app_package = self.is_target_apk(apk_path)
            if not is_target:
                self.log(f"Excluding APK: {apk_name} (reason: {app_package})")
                return False
            
            self.log(f"Processing APK: {apk_name} (app package: {app_package})")
            
            # Extract and analyze DEX files
            packages_in_apk = set()
            dex_files_processed = 0
            
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Find all DEX files
                dex_files = [f for f in apk_zip.filelist if f.filename.endswith('.dex')]
                
                if not dex_files:
                    self.log(f"No DEX files found in {apk_name}", "WARNING")
                    return False
                
                self.log(f"Found {len(dex_files)} DEX files in {apk_name}")
                
                # Process each DEX file
                for dex_file in dex_files:
                    self.log(f"Processing {dex_file.filename} from {apk_name}")
                    
                    try:
                        dex_data = apk_zip.read(dex_file.filename)
                        dex_packages = self.extract_packages_from_dex(dex_data)
                        
                        self.log(f"Found {len(dex_packages)} unique packages in {dex_file.filename}")
                        
                        # Add to APK's package set (deduplication within APK)
                        packages_in_apk.update(dex_packages)
                        dex_files_processed += 1
                        
                    except Exception as e:
                        self.log(f"Error processing {dex_file.filename}: {e}", "ERROR")
                        continue
            
            # Record results
            if packages_in_apk and dex_files_processed > 0:
                self.apk_packages[apk_name] = packages_in_apk
                
                # Update global statistics
                for package in packages_in_apk:
                    self.package_usage[package].add(apk_name)
                    self.global_package_stats[package] += 1
                
                self.processed_apks.append({
                    'name': apk_name,
                    'path': apk_path,
                    'app_package': app_package,
                    'dex_files_processed': dex_files_processed,
                    'packages_found': len(packages_in_apk),
                    'packages': sorted(list(packages_in_apk))
                })
                
                self.log(f"Successfully processed {apk_name}: {len(packages_in_apk)} packages from {dex_files_processed} DEX files")
                return True
            else:
                self.log(f"No valid packages found in {apk_name}", "WARNING")
                return False
                
        except Exception as e:
            self.log(f"Error analyzing {apk_path}: {e}", "ERROR")
            self.failed_apks.append({
                'name': apk_name,
                'path': apk_path,
                'error': str(e)
            })
            return False
    
    def find_apk_files(self, directory):
        """Recursively find all APK files in directory"""
        apk_files = []
        
        self.log(f"Searching for APK files in: {directory}")
        
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if file.lower().endswith('.apk'):
                        apk_path = os.path.join(root, file)
                        apk_files.append(apk_path)
                        
        except Exception as e:
            self.log(f"Error searching directory {directory}: {e}", "ERROR")
        
        self.log(f"Found {len(apk_files)} APK files")
        return apk_files
    
    def generate_report(self):
        """Generate comprehensive analysis report"""
        report = {
            'analysis_summary': {
                'timestamp': datetime.now().isoformat(),
                'total_apks_found': self.apk_count,
                'target_apks_processed': len(self.processed_apks),
                'failed_apks': len(self.failed_apks),
                'unique_packages_found': len(self.package_usage),
                'total_package_references': sum(self.global_package_stats.values())
            },
            'package_statistics': {
                'most_common_packages': self.global_package_stats.most_common(20),
                'package_usage_distribution': {},
                'packages_by_frequency': {}
            },
            'apk_analysis': {
                'processed_apks': self.processed_apks,
                'failed_apks': self.failed_apks
            },
            'detailed_package_analysis': {}
        }
        
        # Convert sets to lists for JSON serialization
        for package, apk_set in self.package_usage.items():
            report['package_statistics']['package_usage_distribution'][package] = sorted(list(apk_set))
        
        # Generate frequency distribution
        frequency_dist = defaultdict(list)
        for package, apk_set in self.package_usage.items():
            frequency = len(apk_set)
            frequency_dist[frequency].append(package)
        
        # Convert to regular dict and sort
        for freq in frequency_dist:
            frequency_dist[freq] = sorted(frequency_dist[freq])
        
        report['package_statistics']['packages_by_frequency'] = dict(frequency_dist)
        
        # Detailed package analysis
        for package, apk_set in self.package_usage.items():
            report['detailed_package_analysis'][package] = {
                'usage_count': len(apk_set),
                'used_in_apks': sorted(list(apk_set)),
                'percentage_of_apks': round((len(apk_set) / max(len(self.processed_apks), 1)) * 100, 2)
            }
        
        return report
    
    def print_human_readable_report(self, report):
        """Print a human-readable version of the report"""
        print("\n" + "="*80)
        print(" ZEBRA/SYMBOL APK PACKAGE ANALYSIS REPORT")
        print("="*80)
        
        # Summary
        summary = report['analysis_summary']
        print(f"\n📊 ANALYSIS SUMMARY")
        print(f"   Timestamp: {summary['timestamp']}")
        print(f"   Total APKs found: {summary['total_apks_found']}")
        print(f"   Target APKs processed: {summary['target_apks_processed']}")
        print(f"   Failed APKs: {summary['failed_apks']}")
        print(f"   Unique packages found: {summary['unique_packages_found']}")
        print(f"   Total package references: {summary['total_package_references']}")
        
        if summary['target_apks_processed'] == 0:
            print(f"\n⚠️  No processable APKs found. All APKs were either:")
            print(f"     - com.zebra.* or com.symbol.* applications (excluded)")
            print(f"     - Invalid or corrupted APK files")
            print(f"     - APKs without valid DEX files")
            return
        
        # Most common packages
        print(f"\n🔝 TOP 20 MOST COMMON PACKAGES")
        print("   " + "-"*60)
        for i, (package, count) in enumerate(report['package_statistics']['most_common_packages'], 1):
            percentage = (count / max(len(self.processed_apks), 1)) * 100
            print(f"   {i:2d}. {package:<25} {count:3d} APKs ({percentage:5.1f}%)")
        
        # Package frequency distribution
        print(f"\n📈 PACKAGE FREQUENCY DISTRIBUTION")
        print("   " + "-"*60)
        freq_dist = report['package_statistics']['packages_by_frequency']
        for frequency in sorted(freq_dist.keys(), reverse=True):
            packages = freq_dist[frequency]
            print(f"   Used in {frequency:2d} APK(s): {len(packages):3d} packages")
            if frequency >= 2:  # Show packages used in 2+ APKs
                print(f"      Examples: {', '.join(packages[:5])}")
                if len(packages) > 5:
                    print(f"      ... and {len(packages)-5} more")
        
        # APK analysis
        print(f"\n📱 PROCESSED APKs")
        print("   " + "-"*60)
        for apk_info in report['apk_analysis']['processed_apks']:
            print(f"   📦 {apk_info['name']}")
            print(f"      App package: {apk_info['app_package']}")
            print(f"      DEX files: {apk_info.get('dex_files_processed', 'N/A')}")
            print(f"      Packages found: {apk_info['packages_found']}")
            if apk_info['packages']:
                print(f"      Top packages: {', '.join(apk_info['packages'][:5])}")
                if len(apk_info['packages']) > 5:
                    print(f"      ... and {len(apk_info['packages'])-5} more")
            print()
        
        # Failed APKs
        if report['apk_analysis']['failed_apks']:
            print(f"\n❌ FAILED APKs")
            print("   " + "-"*60)
            for failed in report['apk_analysis']['failed_apks']:
                print(f"   📦 {failed['name']}: {failed['error']}")
        
        print("\n" + "="*80)

def main():
    parser = argparse.ArgumentParser(
        description="Analyze Zebra/Symbol APK files for common package usage patterns",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python zebra_package_analyzer_simple.py /path/to/apk/folder
    python zebra_package_analyzer_simple.py /path/to/apk/folder --output results/report.json --verbose
    python zebra_package_analyzer_simple.py . --verbose

Note: This script analyzes only APKs with com.zebra.* or com.symbol.* package names.
It uses DEX analysis to detect and process Zebra/Symbol applications.
        """
    )
    
    parser.add_argument('directory', 
                       help='Directory to search for APK files (recursive)')
    parser.add_argument('--output', '-o',
                       help='Output JSON report file (optional)')
    parser.add_argument('--verbose', '-v',
                       action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Validate directory
    if not os.path.isdir(args.directory):
        print(f"Error: Directory '{args.directory}' does not exist or is not a directory")
        sys.exit(1)
    
    # Initialize analyzer
    analyzer = ZebraPackageAnalyzerSimple(verbose=args.verbose)
    
    try:
        # Find APK files
        apk_files = analyzer.find_apk_files(args.directory)
        analyzer.apk_count = len(apk_files)
        
        if not apk_files:
            print("No APK files found in the specified directory")
            sys.exit(1)
        
        # Process each APK
        print(f"\nProcessing {len(apk_files)} APK files...")
        processed_count = 0
        for i, apk_path in enumerate(apk_files, 1):
            print(f"Progress: {i}/{len(apk_files)} - {os.path.basename(apk_path)}")
            if analyzer.analyze_apk(apk_path):
                processed_count += 1
        
        # Generate report
        report = analyzer.generate_report()
        
        # Save JSON report if requested
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"\n✅ JSON report saved to: {args.output}")
        
        # Print human-readable report
        analyzer.print_human_readable_report(report)
        
        if processed_count > 0:
            print(f"\n✅ Analysis complete! Processed {processed_count} APKs (excluding Zebra/Symbol applications)")
        else:
            print(f"\n⚠️  No processable APKs found in {len(apk_files)} APK files")
            print("   All APKs were either Zebra/Symbol applications (excluded) or invalid")
        
    except KeyboardInterrupt:
        print("\n\n❌ Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Analysis failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
