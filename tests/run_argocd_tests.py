#!/usr/bin/env python3
"""
Simple test runner for ArgoCD tests.
Usage: python run_argocd_tests.py
"""

import os
import sys
import subprocess


def check_environment():
    """Check if required environment variables are set."""
    required_vars = ['APP_TOKEN']
    optional_vars = {
        'SANDBOX_URL': 'http://localhost:8080',
        'ADMIN_TOKEN': 'not needed for ArgoCD tests'
    }
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        print("❌ Missing required environment variables:")
        for var in missing_vars:
            print(f"   - {var}")
        print("\nPlease set these variables and try again.")
        return False
    
    print("✅ Environment check passed:")
    for var in required_vars:
        print(f"   - {var}: {'*' * 8}")  # Don't show actual token
    
    for var, default in optional_vars.items():
        value = os.getenv(var)
        if value:
            print(f"   - {var}: {'*' * 8}")  # Don't show actual token
        else:
            print(f"   - {var}: {default}")
    
    return True


def check_dependencies():
    """Check if Python dependencies are available."""
    print("📦 Checking dependencies...")
    
    # Read requirements from requirements.txt
    required_packages = []
    try:
        with open('requirements.txt', 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Extract package name (before >= or ==)
                    package = line.split('>=')[0].split('==')[0].split('[')[0]
                    required_packages.append(package)
    except FileNotFoundError:
        print("⚠️  requirements.txt not found, using default package list")
        required_packages = ['pytest', 'requests', 'urllib3']
    
    missing_packages = []
    available_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
            available_packages.append(package)
        except ImportError:
            missing_packages.append(package)
    
    if available_packages:
        print("✅ Available packages:")
        for package in available_packages:
            print(f"   - {package}")
    
    if missing_packages:
        print("❌ Missing packages:")
        for package in missing_packages:
            print(f"   - {package}")
        print("\n📄 Please install missing packages using, see requirements.txt")
        return False
    
    print("✅ All required packages are available")
    return True


def run_tests():
    """Run the ArgoCD tests."""
    print("🚀 Running ArgoCD tests...")
    
    # Build pytest command with any additional arguments
    pytest_args = [sys.executable, '-m', 'pytest', 'test_argocd.py', '-v', '-s']
    
    # Add any additional arguments passed to this script
    if len(sys.argv) > 1:
        pytest_args.extend(sys.argv[1:])
    
    try:
        result = subprocess.run(pytest_args, check=False)
        
        if result.returncode == 0:
            print("✅ All tests passed!")
        else:
            print("❌ Some tests failed")
        
        return result.returncode == 0
    except Exception as e:
        print(f"❌ Failed to run tests: {e}")
        return False


def main():
    """Main test runner."""
    print("🧪 ArgoCD Functional Test Runner")
    print("=" * 40)
    
    # Check environment
    if not check_environment():
        sys.exit(1)
    
    print()
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    print()
    
    # Run tests
    success = run_tests()
    
    print()
    print("=" * 40)
    if success:
        print("🎉 Test run completed successfully!")
        sys.exit(0)
    else:
        print("💥 Test run completed with failures")
        sys.exit(1)


if __name__ == "__main__":
    main()
