#!/usr/bin/env python3
"""
Zebra Package Analyzer - Recursive APK Package Analysis

This script recursively searches for APK files in a given directory,
filters for Zebra/Symbol applications, and analyzes their DEX files
to extract common package usage patterns.

Usage:
    python zebra_package_analyzer.py <directory_path> [--output report.json] [--verbose]

Features:
    - Recursive APK discovery
    - Package name filtering (com.zebra.* and com.symbol.*)
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
import subprocess
from pathlib import Path

class ZebraPackageAnalyzer:
    """Main analyzer class for processing Zebra/Symbol APK files"""
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.apk_count = 0
        self.processed_apks = []
        self.failed_apks = []
        self.package_usage = defaultdict(set)  # package -> set of APK names
        self.apk_packages = defaultdict(set)   # APK name -> set of packages
        self.global_package_stats = Counter()
        
        # Package filtering patterns
        self.target_packages = [
            r'^com\.zebra\.',
            r'^com\.symbol\.'
        ]
        
        # Package patterns to ignore (too short or system packages)
        self.ignore_patterns = [
            r'^[a-z]$',                    # Single character
            r'^[a-z]{2}$',                 # Two characters
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
        """Check if APK is a Zebra/Symbol application by package name"""
        try:
            # Use aapt to get package name
            result = subprocess.run(
                ['aapt', 'dump', 'badging', apk_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith('package:'):
                        # Extract package name from: package: name='com.zebra.example'
                        match = re.search(r"name='([^']+)'", line)
                        if match:
                            package_name = match.group(1)
                            self.log(f"Found package name: {package_name}")
                            
                            # Check if it matches our target patterns
                            for pattern in self.target_packages:
                                if re.match(pattern, package_name):
                                    return True, package_name
                            return False, package_name
            
            # Fallback: analyze APK structure
            return self._analyze_apk_structure(apk_path)
            
        except subprocess.TimeoutExpired:
            self.log(f"aapt timeout for {apk_path}", "WARNING")
            return self._analyze_apk_structure(apk_path)
        except Exception as e:
            self.log(f"Error checking package name for {apk_path}: {e}", "ERROR")
            return self._analyze_apk_structure(apk_path)
    
    def _analyze_apk_structure(self, apk_path):
        """Fallback method to analyze APK structure"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Look for AndroidManifest.xml or classes.dex patterns
                for file_info in apk_zip.filelist:
                    if file_info.filename == 'AndroidManifest.xml':
                        # Try to extract some info from manifest
                        try:
                            manifest_data = apk_zip.read(file_info.filename)
                            # Look for zebra/symbol patterns in binary manifest
                            if b'zebra' in manifest_data.lower() or b'symbol' in manifest_data.lower():
                                return True, "unknown_zebra_symbol"
                        except:
                            pass
                
                # Check for DEX files with zebra/symbol packages
                dex_files = [f for f in apk_zip.filelist if f.filename.endswith('.dex')]
                for dex_file in dex_files[:2]:  # Check first 2 DEX files
                    try:
                        dex_data = apk_zip.read(dex_file.filename)
                        if b'com/zebra' in dex_data or b'com/symbol' in dex_data:
                            return True, "dex_detected_zebra_symbol"
                    except:
                        continue
                
                return False, "not_target"
                
        except Exception as e:
            self.log(f"Error analyzing APK structure {apk_path}: {e}", "ERROR")
            return False, "error"
    
    def extract_packages_from_dex(self, dex_data):
        """Extract package names from DEX file data"""
        packages = set()
        
        try:
            # Convert to string for regex processing, ignore encoding errors
            dex_str = dex_data.decode('utf-8', errors='ignore')
            
            # Pattern to match package names in DEX format: Lcom/example/package;
            # This matches the string table entries in DEX files
            package_patterns = [
                r'L([a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)+)/',  # Standard Lcom/example/package/ format
                r'"([a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)+)"',   # Quoted package names
                r'([a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)+)',     # Direct package references
            ]
            
            for pattern in package_patterns:
                matches = re.findall(pattern, dex_str, re.IGNORECASE)
                for match in matches:
                    # Convert path separators to dots
                    package_name = match.replace('/', '.')
                    
                    # Extract first two components (e.g., com.google from com.google.android.gms)
                    parts = package_name.split('.')
                    if len(parts) >= 2:
                        short_package = f"{parts[0]}.{parts[1]}"
                        
                        # Apply ignore filters
                        if not self._should_ignore_package(short_package):
                            packages.add(short_package)
            
            # Also check binary patterns for more precise extraction
            packages.update(self._extract_binary_packages(dex_data))
            
        except Exception as e:
            self.log(f"Error extracting packages from DEX: {e}", "ERROR")
        
        return packages
    
    def _extract_binary_packages(self, dex_data):
        """Extract packages from binary DEX patterns"""
        packages = set()
        
        try:
            # Look for DEX string table patterns: length + string + null
            # Pattern: \x00\x02-\x7F L package_path ;
            binary_pattern = rb'\x00[\x02-\x7F]L([a-z][a-z0-9/]*(?:\.[a-z][a-z0-9/]*)*);'
            
            matches = re.findall(binary_pattern, dex_data, re.IGNORECASE)
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
            
        except Exception as e:
            self.log(f"Error in binary package extraction: {e}", "ERROR")
        
        return packages
    
    def _should_ignore_package(self, package_name):
        """Check if package should be ignored based on patterns"""
        for pattern in self.ignore_patterns:
            if re.match(pattern, package_name):
                return True
        
        # Additional checks for very short or invalid packages
        if len(package_name) < 4:  # Minimum meaningful package length
            return True
        
        if not re.match(r'^[a-z][a-z0-9]*\.[a-z][a-z0-9]*$', package_name):
            return True
        
        return False
    
    def analyze_apk(self, apk_path):
        """Analyze a single APK file for package usage"""
        apk_name = os.path.basename(apk_path)
        self.log(f"Analyzing APK: {apk_name}")
        
        try:
            # Check if this is a target APK (Zebra/Symbol)
            is_target, package_name = self.is_target_apk(apk_path)
            if not is_target:
                self.log(f"Skipping non-target APK: {apk_name} (package: {package_name})")
                return False
            
            self.log(f"Processing target APK: {apk_name} (package: {package_name})")
            
            # Extract and analyze DEX files
            packages_in_apk = set()
            
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
                        
                    except Exception as e:
                        self.log(f"Error processing {dex_file.filename}: {e}", "ERROR")
                        continue
            
            # Record results
            if packages_in_apk:
                self.apk_packages[apk_name] = packages_in_apk
                
                # Update global statistics
                for package in packages_in_apk:
                    self.package_usage[package].add(apk_name)
                    self.global_package_stats[package] += 1
                
                self.processed_apks.append({
                    'name': apk_name,
                    'path': apk_path,
                    'app_package': package_name,
                    'packages_found': len(packages_in_apk),
                    'packages': sorted(list(packages_in_apk))
                })
                
                self.log(f"Successfully processed {apk_name}: {len(packages_in_apk)} packages")
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
                'package_usage_distribution': dict(self.package_usage),
                'packages_by_frequency': {}
            },
            'apk_analysis': {
                'processed_apks': self.processed_apks,
                'failed_apks': self.failed_apks
            },
            'detailed_package_analysis': {}
        }
        
        # Generate frequency distribution
        frequency_dist = defaultdict(list)
        for package, apk_set in self.package_usage.items():
            frequency = len(apk_set)
            frequency_dist[frequency].append(package)
        
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
        
        # Most common packages
        print(f"\n🔝 TOP 20 MOST COMMON PACKAGES")
        print("   " + "-"*50)
        for i, (package, count) in enumerate(report['package_statistics']['most_common_packages'], 1):
            percentage = (count / max(len(self.processed_apks), 1)) * 100
            print(f"   {i:2d}. {package:<30} {count:3d} APKs ({percentage:5.1f}%)")
        
        # Package frequency distribution
        print(f"\n📈 PACKAGE FREQUENCY DISTRIBUTION")
        print("   " + "-"*50)
        freq_dist = report['package_statistics']['packages_by_frequency']
        for frequency in sorted(freq_dist.keys(), reverse=True):
            packages = freq_dist[frequency]
            print(f"   Used in {frequency:2d} APK(s): {len(packages):3d} packages")
            if frequency >= 3:  # Show packages used in 3+ APKs
                print(f"      Examples: {', '.join(packages[:5])}")
                if len(packages) > 5:
                    print(f"      ... and {len(packages)-5} more")
        
        # APK analysis
        print(f"\n📱 PROCESSED APKs")
        print("   " + "-"*50)
        for apk_info in report['apk_analysis']['processed_apks']:
            print(f"   {apk_info['name']}")
            print(f"      App package: {apk_info['app_package']}")
            print(f"      Packages found: {apk_info['packages_found']}")
            print(f"      Top packages: {', '.join(apk_info['packages'][:5])}")
            if len(apk_info['packages']) > 5:
                print(f"      ... and {len(apk_info['packages'])-5} more")
        
        # Failed APKs
        if report['apk_analysis']['failed_apks']:
            print(f"\n❌ FAILED APKs")
            print("   " + "-"*50)
            for failed in report['apk_analysis']['failed_apks']:
                print(f"   {failed['name']}: {failed['error']}")
        
        print("\n" + "="*80)

def main():
    parser = argparse.ArgumentParser(
        description="Analyze Zebra/Symbol APK files for common package usage patterns",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python zebra_package_analyzer.py /path/to/apk/folder
    python zebra_package_analyzer.py /path/to/apk/folder --output report.json --verbose
    python zebra_package_analyzer.py . --verbose
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
    analyzer = ZebraPackageAnalyzer(verbose=args.verbose)
    
    try:
        # Find APK files
        apk_files = analyzer.find_apk_files(args.directory)
        analyzer.apk_count = len(apk_files)
        
        if not apk_files:
            print("No APK files found in the specified directory")
            sys.exit(1)
        
        # Process each APK
        print(f"\nProcessing {len(apk_files)} APK files...")
        for i, apk_path in enumerate(apk_files, 1):
            print(f"Progress: {i}/{len(apk_files)} - {os.path.basename(apk_path)}")
            analyzer.analyze_apk(apk_path)
        
        # Generate report
        report = analyzer.generate_report()
        
        # Save JSON report if requested
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"\n✅ JSON report saved to: {args.output}")
        
        # Print human-readable report
        analyzer.print_human_readable_report(report)
        
        print(f"\n✅ Analysis complete! Processed {len(analyzer.processed_apks)} target APKs")
        
    except KeyboardInterrupt:
        print("\n\n❌ Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Analysis failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
