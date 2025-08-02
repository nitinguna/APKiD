import yara

try:
    print("Attempting to compile obfuscators.yara...")
    rules = yara.compile('obfuscators.yara')
    print("SUCCESS: obfuscators.yara compiled successfully!")
    
    rule_names = [rule.identifier for rule in rules]
    print(f"Found {len(rule_names)} rules:")
    for name in rule_names:
        print(f"  - {name}")
    
    if 'massive_name_obfuscation' in rule_names:
        print("✅ massive_name_obfuscation rule found and compiled successfully!")
    else:
        print("❌ massive_name_obfuscation rule not found")
        
except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()
