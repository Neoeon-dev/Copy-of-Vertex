# Simple test to verify imports work without database connection
print("Testing imports...")

# Test 1: Import extract_iocs_from_email
try:
    from app.threat_intel import extract_iocs_from_email
    print("✓ Successfully imported extract_iocs_from_email from threat_intel")
except Exception as e:
    print(f"✗ Failed to import extract_iocs_from_email: {e}")

# Test 2: Import CorrelationEngine
try:
    from app.forensics.correlation import CorrelationEngine
    print("✓ Successfully imported CorrelationEngine from forensics.correlation")
except Exception as e:
    print(f"✗ Failed to import CorrelationEngine: {e}")

# Test 3: Instantiate CorrelationEngine
try:
    engine = CorrelationEngine()
    print("✓ Successfully instantiated CorrelationEngine")
except Exception as e:
    print(f"✗ Failed to instantiate CorrelationEngine: {e}")

# Test 4: Check if add_email method exists
try:
    engine = CorrelationEngine()
    if hasattr(engine, 'add_email'):
        print("✓ add_email method exists on CorrelationEngine")
    else:
        print("✗ add_email method missing from CorrelationEngine")
except Exception as e:
    print(f"✗ Error checking add_email method: {e}")

# Test 5: Check if extract_iocs_from_email is referenced in add_email
try:
    engine = CorrelationEngine()
    import inspect
    source = inspect.getsource(engine.add_email)
    if 'extract_iocs_from_email' in source:
        print("✓ extract_iocs_from_email is referenced in add_email method")
    else:
        print("✗ extract_iocs_from_email NOT found in add_email method")
except Exception as e:
    print(f"✗ Error checking add_email source: {e}")

print("\nImport testing complete!")