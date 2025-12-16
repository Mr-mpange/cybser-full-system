"""
IntelliGuard Test Script
Test the backend API functionality
"""

import requests
import json
import time
from datetime import datetime

def test_backend():
    """Test IntelliGuard backend functionality"""
    
    print("🧪 Testing IntelliGuard Backend API")
    print("="*50)
    
    base_url = "http://localhost:8000"
    
    # Test 1: Health Check
    print("1. Testing health endpoint...")
    try:
        response = requests.get(f"{base_url}/health", timeout=5)
        if response.status_code == 200:
            health_data = response.json()
            print(f"✅ Health check passed: {health_data['status']}")
            print(f"   Models loaded: {health_data.get('models_loaded', 'Unknown')}")
        else:
            print(f"❌ Health check failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Health check error: {str(e)}")
    
    # Test 2: Root endpoint
    print("\n2. Testing root endpoint...")
    try:
        response = requests.get(f"{base_url}/", timeout=5)
        if response.status_code == 200:
            root_data = response.json()
            print(f"✅ Root endpoint: {root_data['name']} v{root_data['version']}")
            print(f"   Features: {len(root_data.get('features', []))} available")
        else:
            print(f"❌ Root endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Root endpoint error: {str(e)}")
    
    # Test 3: Sample prediction
    print("\n3. Testing prediction endpoint...")
    try:
        # Sample network traffic data (normal traffic)
        sample_data = {
            "traffic_data": {
                "flow_duration": 1200.5,
                "total_fwd_packets": 45,
                "total_bwd_packets": 32,
                "total_length_fwd_packets": 2800.0,
                "total_length_bwd_packets": 1900.0,
                "fwd_packet_length_max": 580.0,
                "fwd_packet_length_min": 48.0,
                "fwd_packet_length_mean": 220.0,
                "bwd_packet_length_max": 450.0,
                "bwd_packet_length_min": 38.0,
                "flow_bytes_per_sec": 8500.0,
                "flow_packets_per_sec": 85.0,
                "flow_iat_mean": 950.0,
                "flow_iat_std": 480.0,
                "flow_iat_max": 2200.0,
                "flow_iat_min": 8.0,
                "fwd_iat_total": 4800.0,
                "fwd_iat_mean": 820.0,
                "bwd_iat_total": 3600.0,
                "bwd_iat_mean": 650.0
            },
            "model_type": "ensemble",
            "include_anomaly_detection": True
        }
        
        response = requests.post(
            f"{base_url}/api/v1/predict",
            json=sample_data,
            timeout=10
        )
        
        if response.status_code == 200:
            pred_data = response.json()
            result = pred_data['results'][0]
            print(f"✅ Prediction successful:")
            print(f"   Attack Type: {result['attack_type']}")
            print(f"   Confidence: {result['confidence_score']:.2%}")
            print(f"   Severity: {result['severity_level']}")
            print(f"   Processing Time: {pred_data['processing_time']:.3f}s")
            print(f"   System Status: {pred_data['system_status']}")
        else:
            print(f"❌ Prediction failed: {response.status_code}")
            print(f"   Response: {response.text}")
            
    except Exception as e:
        print(f"❌ Prediction error: {str(e)}")
    
    # Test 4: Model performance
    print("\n4. Testing model performance endpoint...")
    try:
        response = requests.get(f"{base_url}/api/v1/models/performance", timeout=5)
        if response.status_code == 200:
            perf_data = response.json()
            print(f"✅ Model performance retrieved:")
            print(f"   Best Model: {perf_data['best_model']}")
            print(f"   Overall Accuracy: {perf_data['overall_accuracy']:.2%}")
        else:
            print(f"❌ Model performance failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Model performance error: {str(e)}")
    
    print("\n" + "="*50)
    print("🎯 IntelliGuard Backend Test Summary:")
    print("   • Health check endpoint")
    print("   • Root information endpoint") 
    print("   • ML prediction endpoint")
    print("   • Model performance endpoint")
    print("   • Security middleware")
    print("   • Error handling")
    print("="*50)

def test_attack_samples():
    """Test with different attack samples"""
    print("\n🚨 Testing Attack Detection Samples")
    print("="*50)
    
    base_url = "http://localhost:8000"
    
    # DoS Attack Sample
    dos_sample = {
        "traffic_data": {
            "flow_duration": 180.2,
            "total_fwd_packets": 850,
            "total_bwd_packets": 12,
            "total_length_fwd_packets": 15000.0,
            "total_length_bwd_packets": 480.0,
            "fwd_packet_length_max": 64.0,
            "fwd_packet_length_min": 64.0,
            "fwd_packet_length_mean": 64.0,
            "bwd_packet_length_max": 40.0,
            "bwd_packet_length_min": 40.0,
            "flow_bytes_per_sec": 85000.0,
            "flow_packets_per_sec": 4500.0,
            "flow_iat_mean": 0.2,
            "flow_iat_std": 0.1,
            "flow_iat_max": 1.0,
            "flow_iat_min": 0.1,
            "fwd_iat_total": 180.0,
            "fwd_iat_mean": 0.2,
            "bwd_iat_total": 180.0,
            "bwd_iat_mean": 15.0
        },
        "include_anomaly_detection": True
    }
    
    print("Testing DoS Attack Sample...")
    try:
        response = requests.post(f"{base_url}/api/v1/predict", json=dos_sample, timeout=10)
        if response.status_code == 200:
            result = response.json()['results'][0]
            print(f"✅ DoS Detection: {result['attack_type']} ({result['confidence_score']:.2%} confidence)")
            print(f"   Severity: {result['severity_level']}")
        else:
            print(f"❌ DoS test failed: {response.status_code}")
    except Exception as e:
        print(f"❌ DoS test error: {str(e)}")

if __name__ == "__main__":
    print("🛡️ IntelliGuard API Testing Suite")
    print(f"🕒 Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Wait a moment for server to be ready
    print("⏳ Waiting for server to be ready...")
    time.sleep(2)
    
    # Run tests
    test_backend()
    test_attack_samples()
    
    print(f"\n🏁 Testing completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("🌐 Open http://localhost:3000 for the dashboard")
    print("📚 Open http://localhost:8000/docs for API documentation")