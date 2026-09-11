from app.forensics.correlation import CorrelationEngine
from app.db import SessionLocal, engine
from app.models import Base, Email
import asyncio

# Create tables
Base.metadata.create_all(bind=engine)

# Test instantiation
def test_correlation_engine():
    try:
        engine = CorrelationEngine()
        print("✓ CorrelationEngine instantiated successfully")

        # Test that it has the enhanced add_email method
        if hasattr(engine, 'add_email'):
            print("✓ add_email method exists")
        else:
            print("✗ add_email method missing")

        # Check if it imports the extract_iocs_from_email function
        import inspect
        source = inspect.getsource(engine.add_email)
        if 'extract_iocs_from_email' in source:
            print("✓ extract_iocs_from_email is referenced in add_email")
        else:
            print("✗ extract_iocs_from_email not found in add_email")

        return True
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

if __name__ == "__main__":
    test_correlation_engine()