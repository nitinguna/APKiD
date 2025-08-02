#!/usr/bin/env python3

import sys
import os

# Add APKiD to path for imports
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

from apkid.rules import RulesManager

def recompile_all_rules():
    """Recompile all APKiD rules including our updated debug rules"""
    try:
        print("🔧 Recompiling all APKiD rules...")
        
        # Create rules manager
        rules_manager = RulesManager()
        
        # Compile all rules (this will include our updated obfuscators.yara)
        rules = rules_manager.compile()
        
        # Save to master rules.yarc
        rules_count = rules_manager.save()
        
        print(f"✅ Successfully compiled and saved {rules_count} rules to rules.yarc")
        
        # Check if our debug rules are included
        print("\n🔍 Checking for debug rules in compiled output...")
        
        # Get the rule identifiers (unfortunately YARA doesn't expose rule names easily)
        rule_ids = [r.identifier for r in rules]
        
        debug_rule_names = [
            'massive_obf_method1_single_char_strings',
            'massive_obf_method2_single_char_classes', 
            'massive_obf_method3_two_char_classes',
            'massive_obf_method3b_three_char_classes',
            'massive_obf_method4_single_char_methods',
            'massive_obf_method5_extreme_combined',
            'massive_name_obfuscation'
        ]
        
        found_debug_rules = []
        for rule_name in debug_rule_names:
            if rule_name in rule_ids:
                found_debug_rules.append(rule_name)
                print(f"✅ Found: {rule_name}")
            else:
                print(f"❌ Missing: {rule_name}")
        
        print(f"\n📊 Found {len(found_debug_rules)} out of {len(debug_rule_names)} debug rules")
        
        return True
        
    except Exception as e:
        print(f"❌ Error recompiling rules: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    recompile_all_rules()
