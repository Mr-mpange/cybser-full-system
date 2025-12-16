#!/usr/bin/env python3
"""
Quick Test Script for IntelliGuard
Verify that the system can start and basic functionality works
"""

import sys
import subprocess
import time
import requests
import json

def test_python_installation():
    """Test if Python is properly installed"""
    print("🐍 Testing Python installation...")
    try:
        version = sys.version_info
        if version.major >= 3 and version.minor >= 8:
            print(f"✅ Python {version.major}.{version.minor}.{version.micro} - OK")
            return True
        else:
            print(f"❌ Python {version.major}.{version.minor}.{version.micro} - Need 3.8+")
            return False
    except Exception as e:
        print(f"❌ Python test failed: {e}")
        return False

def test_dependencies():
    """Test if key dependencies can be imported"""
    print("📦 Testing key dependencies...")
    
    dependencies = [
        'fastapi',
        'uvicorn', 
        'pandas',
        'numpy',
        'sklearn',
        'pydantic'
    ]
    
    failed = []
    for dep in dependencies:
        try:
            __import__(dep)
            print(f"✅ {dep} - OK")
        except ImportError:
            print(f"❌ {dep} - Missing")
            failed.append(dep)
    
    if failed:
        print(f"\n📥 Installing missing dependencies: {', '.join(failed)}")
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
            ])
            print("✅ Dependencies installed successfully")
            return True
        except subprocess.CalledProcessError:
            print("❌ Failed to install dependencies")
            return False
    
    return True

def test_backend_import():
    """Test if backend modules can be imported"""
    print("🔧 Testing backend imports...")
    
    try:
        sys.path.append('backend')
        from app.main import app
        print("✅ Backend app import - OK")
        return True
    except Exception as e:
        print(f"❌ Backend import failed: {e}")
        return False

def test_api_response():
    """Test if API responds (if running)"""
    print("🌐 Testing API response...")
    
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ API Health Check - {data.get('status', 'OK')}")
            return True
        else:
            print(f"⚠️  API returned status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("⚠️  API not running (this is OK if you haven't started it yet)")
        return True
    except Exception as e:
        print(f"❌ API test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🧪 IntelliGuard Quick Test")
    print("=" * 50)
    
    tests = [
        ("Python Installation", test_python_installation),
        ("Dependencies", test_dependencies),
        ("Backend Import", test_backend_import),
        ("API Response", test_api_response)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n🔍 {test_name}:")
        if test_func():
            passed += 1
        print("-" * 30)
    
    print(f"\n📊 Test Results: {passed}/{total} passed")
    
    if passed == total:
        print("🎉 All tests passed! IntelliGuard is ready to run.")
        print("\n🚀 To start the system:")
        print("   Windows: start_all.bat")
        print("   Linux/macOS: ./start_all.sh")
    else:
        print("⚠️  Some tests failed. Please check the errors above.")
        print("\n💡 Try installing dependencies manually:")
        print("   pip install -r requirements.txt")
        print("   pip install -r backend/requirements.txt")

if __name__ == "__main__":
    main()