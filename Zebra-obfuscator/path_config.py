#!/usr/bin/env python3
"""
Path Configuration Module for Zebra-obfuscator
Centralizes all path management for configurations and results
"""

import os
import json
from pathlib import Path

class ZebraPathConfig:
    """Manages all paths for Zebra-obfuscator components"""
    
    def __init__(self, base_dir=None):
        """
        Initialize path configuration
        
        Args:
            base_dir: Base directory (defaults to script's directory)
        """
        if base_dir is None:
            self.base_dir = Path(__file__).parent
        else:
            self.base_dir = Path(base_dir)
        
        # Define folder structure
        self.config_dir = self.base_dir / "configurations"
        self.results_dir = self.base_dir / "results"
        self.samples_dir = self.base_dir / "test-samples"
        
        # Ensure directories exist
        self._ensure_directories()
    
    def _ensure_directories(self):
        """Create directories if they don't exist"""
        for directory in [self.config_dir, self.results_dir, self.samples_dir]:
            directory.mkdir(exist_ok=True)
    
    # Configuration file paths
    @property
    def zebra_sdk_config(self):
        """Path to discovered Zebra SDK configuration"""
        return self.config_dir / "discovered_zebra_sdk_config.json"
    
    @property
    def obfuscation_rules_config(self):
        """Path to obfuscation rules configuration"""
        return self.config_dir / "obfuscation_rules_config.json"
    
    @property
    def unknown_sdk_config(self):
        """Path to unknown SDK discovery configuration"""
        return self.config_dir / "unknownSDKDiscovery.json"
    
    # Result file paths
    @property
    def quick_analysis_results(self):
        """Path to quick analysis results JSON"""
        return self.results_dir / "quick_analysis_results.json"
    
    @property 
    def csv_results(self):
        """Path to CSV analysis results"""
        return self.results_dir / "apk_analysis_results.csv"
    
    @property
    def comprehensive_results(self):
        """Path to comprehensive analysis results"""
        return self.results_dir / "comprehensive_analysis_results.json"
    
    @property
    def package_analyzer_results(self):
        """Path to package analyzer results"""
        return self.results_dir / "package_analysis_report.json"
    
    # Utility methods
    def get_config_path(self, config_name):
        """
        Get path to a configuration file
        
        Args:
            config_name: Name of the configuration file
            
        Returns:
            Path object for the configuration file
        """
        return self.config_dir / config_name
    
    def get_results_path(self, results_name):
        """
        Get path to a results file
        
        Args:
            results_name: Name of the results file
            
        Returns:
            Path object for the results file
        """
        return self.results_dir / results_name
    
    def load_config(self, config_name):
        """
        Load a JSON configuration file
        
        Args:
            config_name: Name of the configuration file
            
        Returns:
            Dictionary with configuration data or None if file doesn't exist
        """
        config_path = self.get_config_path(config_name)
        
        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                print(f"⚠️  Configuration file not found: {config_path}")
                return None
        except json.JSONDecodeError as e:
            print(f"❌ Error loading configuration {config_name}: {e}")
            return None
        except Exception as e:
            print(f"❌ Error reading configuration {config_name}: {e}")
            return None
    
    def save_config(self, config_name, config_data):
        """
        Save configuration data to JSON file
        
        Args:
            config_name: Name of the configuration file
            config_data: Dictionary with configuration data
            
        Returns:
            True if saved successfully, False otherwise
        """
        config_path = self.get_config_path(config_name)
        
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
            print(f"✅ Configuration saved: {config_path}")
            return True
        except Exception as e:
            print(f"❌ Error saving configuration {config_name}: {e}")
            return False
    
    def save_results(self, results_name, results_data):
        """
        Save results data to JSON file
        
        Args:
            results_name: Name of the results file
            results_data: Dictionary with results data
            
        Returns:
            True if saved successfully, False otherwise
        """
        results_path = self.get_results_path(results_name)
        
        try:
            with open(results_path, 'w', encoding='utf-8') as f:
                json.dump(results_data, f, indent=2, ensure_ascii=False)
            print(f"✅ Results saved: {results_path}")
            return True
        except Exception as e:
            print(f"❌ Error saving results {results_name}: {e}")
            return False
    
    def list_configs(self):
        """
        List all available configuration files
        
        Returns:
            List of configuration file names
        """
        if self.config_dir.exists():
            return [f.name for f in self.config_dir.glob("*.json")]
        return []
    
    def list_results(self):
        """
        List all available results files
        
        Returns:
            List of results file names
        """
        if self.results_dir.exists():
            return [f.name for f in self.results_dir.glob("*")]
        return []
    
    def get_status(self):
        """
        Get status information about the configuration
        
        Returns:
            Dictionary with status information
        """
        return {
            "base_directory": str(self.base_dir),
            "config_directory": str(self.config_dir),
            "results_directory": str(self.results_dir),
            "samples_directory": str(self.samples_dir),
            "directories_exist": {
                "configurations": self.config_dir.exists(),
                "results": self.results_dir.exists(),
                "test_samples": self.samples_dir.exists()
            },
            "available_configs": self.list_configs(),
            "available_results": self.list_results()
        }
    
    def print_status(self):
        """Print status information"""
        status = self.get_status()
        
        print("📁 Zebra-obfuscator Path Configuration")
        print("=" * 40)
        print(f"📂 Base Directory: {status['base_directory']}")
        print(f"⚙️  Config Directory: {status['config_directory']}")
        print(f"📊 Results Directory: {status['results_directory']}")
        print(f"🧪 Samples Directory: {status['samples_directory']}")
        
        print("\n📋 Directory Status:")
        for dir_name, exists in status['directories_exist'].items():
            status_icon = "✅" if exists else "❌"
            print(f"   {status_icon} {dir_name}")
        
        if status['available_configs']:
            print(f"\n⚙️  Available Configurations ({len(status['available_configs'])}):")
            for config in status['available_configs']:
                print(f"   📄 {config}")
        
        if status['available_results']:
            print(f"\n📊 Available Results ({len(status['available_results'])}):")
            for result in status['available_results']:
                print(f"   📄 {result}")

# Global instance for easy import
zebra_paths = ZebraPathConfig()

def get_zebra_paths():
    """Get the global ZebraPathConfig instance"""
    return zebra_paths

# Convenience functions for common paths
def get_config_path(config_name="obfuscation_rules_config.json"):
    """Get path to configuration file"""
    return str(zebra_paths.get_config_path(config_name))

def get_results_path(results_name="quick_analysis_results.json"):
    """Get path to results file"""
    return str(zebra_paths.get_results_path(results_name))

def get_quick_analysis_results_path():
    """Get path to quick analysis results"""
    return str(zebra_paths.quick_analysis_results)

def get_csv_results_path():
    """Get path to CSV results"""
    return str(zebra_paths.csv_results)

if __name__ == "__main__":
    # Print status when run directly
    zebra_paths.print_status()
