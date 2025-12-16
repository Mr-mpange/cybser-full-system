# IntelliGuard 🛡️

**Advanced Cyber Attack Detection System with Machine Learning**

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com)
[![ML](https://img.shields.io/badge/ML-96%25%20Accuracy-red.svg)](https://scikit-learn.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## 🚀 Quick Start (30 Seconds)

### 1. Download & Setup
```bash
git clone https://github.com/your-username/intelliguard.git
cd intelliguard
```

### 2. Start the System
**Windows:**
```cmd
start_all.bat
```

**Linux/macOS:**
```bash
chmod +x start_all.sh
./start_all.sh
```

### 3. Access IntelliGuard
- **🎛️ Web Dashboard**: http://localhost:3001
- **🌐 API Server**: http://localhost:8000
- **📚 Interactive Docs**: http://localhost:8000/docs
- **💓 Health Check**: http://localhost:8000/health

### 4. Test the System (Optional)
```bash
python quick_test.py
python test_intelliguard.py
```

## ✨ What You Get

- **🧠 96%+ Accuracy** - Advanced ML models (XGBoost, Random Forest, Neural Networks)
- **⚡ Real-time Detection** - Process network traffic data instantly
- **🔍 Zero-day Detection** - Identify unknown threats using anomaly detection
- **📊 REST API** - Production-ready FastAPI with interactive documentation
- **🚨 Smart Alerts** - Email, Telegram, and webhook notifications
- **📈 Monitoring** - System health and performance tracking
- **🔒 Enterprise Security** - Rate limiting, validation, audit logging

## 🎯 Supported Attack Types

| Attack Type | Description | Detection Method |
|-------------|-------------|------------------|
| **Normal Traffic** | Baseline network activity | ML Classification |
| **DoS/DDoS** | Denial of Service attacks | High packet rate patterns |
| **Port Scan** | Network reconnaissance | Small packet scanning patterns |
| **Botnet** | Compromised device networks | Periodic communication patterns |
| **Infiltration** | Unauthorized access attempts | Anomalous access patterns |
| **Zero-day** | Unknown attack patterns | Anomaly detection algorithms |

## 📁 Project Structure

```
intelliguard/
├── 📁 backend/                 # FastAPI backend application
├── 📁 frontend/               # Web dashboard interface
│   ├── 📁 app/                # Main application code
│   │   ├── 📁 api/            # API endpoints
│   │   ├── 📁 core/           # Core functionality (config, database, cache)
│   │   ├── 📁 models/         # Data models and ML models
│   │   ├── 📁 services/       # Business logic services
│   │   └── 📁 utils/          # Utility functions
│   ├── 📁 ml_models/          # Machine learning models storage
│   └── 📄 requirements.txt    # Backend dependencies

├── 📁 data/                   # Sample data and datasets
├── 📁 models/                 # Trained ML models
├── 📁 notebooks/              # Data analysis scripts
├── 📁 results/                # Analysis results and visualizations
├── 📄 start_all.bat          # 🚀 Windows startup script
├── 📄 start_all.sh           # 🚀 Linux/macOS startup script
├── 📄 stop_all.bat           # 🛑 Windows stop script
├── 📄 quick_test.py          # 🧪 System verification
├── 📄 test_intelliguard.py   # 🔧 API testing script
├── 📄 requirements.txt       # Core dependencies
├── 📄 .env.example           # Environment configuration template
└── 📄 README.md              # This file
```

## 🚀 Startup Scripts

### What the Scripts Do Automatically
1. ✅ **Check Python** - Verify Python 3.8+ installation
2. 📦 **Install Dependencies** - Auto-install required packages
3. 🔧 **Setup Environment** - Create `.env` configuration file
4. 📁 **Create Directories** - Make logs, uploads, temp folders
5. 🚀 **Start Backend** - Launch FastAPI server on port 8000
6. 🌐 **Start Dashboard** - Launch web dashboard on port 3001
7. 📊 **Display URLs** - Show all service endpoints

### Windows (`start_all.bat`)
- ✅ Automatic dependency installation
- 🔧 Environment setup
- 🚀 Service startup with error handling
- 📊 Service URL display

### Linux/macOS (`start_all.sh`)
- 🐧 Cross-platform compatibility
- 🔄 Background process management
- 🛑 Graceful shutdown with Ctrl+C
- 📝 Colored output for better readability

### Stop the System
**Windows:**
```cmd
stop_all.bat
```

**Linux/macOS:**
```bash
# Press Ctrl+C in the terminal where you started the system
```

## 📡 API Usage

### Single Prediction
```bash
curl -X POST "http://localhost:8000/api/v1/predict/single" \
  -H "Content-Type: application/json" \
  -d '{
    "network_data": {
      "flow_duration": 1.5,
      "total_fwd_packets": 10,
      "total_bwd_packets": 8,
      "flow_bytes_per_sec": 1500.0,
      "flow_packets_per_sec": 12.0,
      "flow_iat_mean": 0.1,
      "flow_iat_std": 0.05,
      "fwd_packet_length_mean": 150.0,
      "bwd_packet_length_mean": 120.0
    }
  }'
```

### Batch Prediction
```bash
curl -X POST "http://localhost:8000/api/v1/predict/batch" \
  -H "Content-Type: application/json" \
  -d '{
    "network_data": [
      {
        "flow_duration": 1.5,
        "total_fwd_packets": 10,
        ...
      },
      {
        "flow_duration": 2.1,
        "total_fwd_packets": 15,
        ...
      }
    ]
  }'
```

### File Upload
```bash
curl -X POST "http://localhost:8000/api/v1/predict/file" \
  -F "file=@network_data.csv"
```

### System Health
```bash
curl "http://localhost:8000/health"
```

## 🔧 Configuration

### Environment Variables (.env)
The system automatically creates a `.env` file with defaults. You can customize:

```env
# Application Settings
APP_NAME=IntelliGuard
DEBUG=true
LOG_LEVEL=INFO

# API Configuration
SECRET_KEY=change-this-in-production
ALLOWED_HOSTS=localhost,127.0.0.1
CORS_ORIGINS=http://localhost:3000

# File Upload
MAX_FILE_SIZE=52428800  # 50MB
UPLOAD_DIR=uploads

# ML Models
MODEL_DIR=backend/ml_models/trained_models
MODEL_VERSION=v1.0

# Email Alerts (Optional)
SMTP_HOST=smtp.gmail.com
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# Telegram Alerts (Optional)
TELEGRAM_BOT_TOKEN=your-bot-token
TELEGRAM_CHAT_ID=your-chat-id

# Webhook Alerts (Optional)
WEBHOOK_URL=https://your-webhook-endpoint.com/alerts
```

## 🧠 Machine Learning Models

### Available Models
1. **Optimized XGBoost** - 96.0% accuracy, best overall performance
2. **Random Forest** - 95.9% accuracy, robust and interpretable
3. **Neural Network** - 95.8% accuracy, deep learning approach
4. **Gradient Boosting** - 95.7% accuracy, ensemble method
5. **SVM** - 94.5% accuracy, support vector machine
6. **Ensemble** - Combines multiple models for best results

### Model Performance
| Model | Accuracy | Precision | Recall | F1-Score |
|-------|----------|-----------|--------|----------|
| XGBoost | 96.0% | 95.5% | 90.8% | 93.1% |
| Random Forest | 95.9% | 95.4% | 90.7% | 93.0% |
| Neural Network | 95.8% | 95.3% | 90.6% | 92.9% |
| Ensemble | 96.2% | 95.7% | 91.0% | 93.3% |

### Zero-day Detection
- **Isolation Forest** algorithm for anomaly detection
- Identifies unknown attack patterns
- Configurable sensitivity threshold
- Real-time anomaly scoring

## 📊 Monitoring & Analytics

### System Metrics
- **Performance**: CPU, memory, disk usage
- **API Metrics**: Request count, response times, error rates
- **ML Metrics**: Prediction accuracy, model performance
- **Security Events**: Threat detections, alert statistics

### Health Monitoring
```python
# Check system health
GET /health

# Get detailed metrics
GET /api/v1/metrics

# View system dashboard
GET /api/v1/dashboard
```

## 🚨 Alert System

### Supported Channels
- **📧 Email**: SMTP-based email notifications
- **📱 Telegram**: Bot-based instant messaging
- **🔗 Webhooks**: HTTP POST to custom endpoints
- **📋 Logs**: File-based logging with rotation

### Alert Configuration
Configure alerts in `.env`:
```env
# Email
SMTP_HOST=smtp.gmail.com
SMTP_USER=alerts@company.com
SMTP_PASSWORD=app-password

# Telegram
TELEGRAM_BOT_TOKEN=123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11
TELEGRAM_CHAT_ID=-1001234567890

# Webhook
WEBHOOK_URL=https://your-webhook-endpoint.com/alerts
```

## 🔒 Security Features

### Built-in Security
- **Input Validation**: Comprehensive data validation
- **Rate Limiting**: Protection against abuse
- **CORS Protection**: Cross-origin request security
- **Security Headers**: HSTS, CSP, X-Frame-Options
- **Audit Logging**: Complete request/response logging

### Best Practices
1. **Change Default Secrets**: Update SECRET_KEY in production
2. **Use HTTPS**: Enable TLS in production environments
3. **Regular Updates**: Keep dependencies updated
4. **Monitor Logs**: Review security logs regularly
5. **Backup Data**: Implement regular backup procedures

## 🧪 Testing

### System Verification
```bash
# Test system setup
python quick_test.py
```

### API Testing
```bash
# Test API functionality
python test_intelliguard.py
```

### Load Testing
```bash
# Install load testing tools
pip install locust

# Run load tests
locust -f tests/load_test.py --host=http://localhost:8000
```

## 🛠️ Development

### Setup Development Environment
```bash
# Clone repository
git clone https://github.com/your-username/intelliguard.git
cd intelliguard

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
pip install -r backend/requirements.txt

# Run in development mode
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Code Quality
```bash
# Format code
black backend/app/
isort backend/app/

# Lint code
flake8 backend/app/

# Type checking
mypy backend/app/
```

## 📚 Documentation

### API Documentation
- **Interactive Docs**: http://localhost:8000/docs (Swagger UI)
- **ReDoc**: http://localhost:8000/redoc (Alternative documentation)
- **OpenAPI Schema**: http://localhost:8000/openapi.json

### Additional Resources
- **Model Training**: See `notebooks/` for analysis scripts
- **Data Analysis**: Sample analysis scripts in `notebooks/`
- **Configuration**: Environment variable reference above
- **Troubleshooting**: Common issues and solutions below

## 🆘 Troubleshooting

### Common Issues

**❌ "Python not found"**
- Install Python 3.8+ from https://python.org
- Make sure Python is in your PATH

**❌ "pip not found"**
- Reinstall Python with pip included
- Or install pip separately

**❌ "Port 8000 already in use"**
- Stop other services using port 8000: `netstat -ano | findstr :8000`
- Or change the port in the startup script

**❌ "Dependencies installation failed"**
- Update pip: `pip install --upgrade pip`
- Install manually: `pip install -r requirements.txt`

**❌ "Models not loading"**
- Check if `backend/ml_models/trained_models/` directory exists
- The system will work with basic models if trained models are missing

### Getting Help
1. **Check Logs**: Look in the `logs/` directory
2. **Test Script**: Run `python quick_test.py`
3. **API Health**: Visit http://localhost:8000/health
4. **Documentation**: Check http://localhost:8000/docs

## 🤝 Contributing

We welcome contributions! Please:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Guidelines
- Follow PEP 8 style guidelines
- Add tests for new features
- Update documentation as needed
- Ensure all tests pass before submitting

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Scikit-learn** - Machine learning library
- **FastAPI** - Modern web framework
- **Pandas** - Data manipulation and analysis
- **NumPy** - Numerical computing
- **XGBoost** - Gradient boosting framework

---

**IntelliGuard** - Protecting your digital assets with advanced AI-powered threat detection.

*Made with ❤️ for cybersecurity professionals and researchers*

## 🎯 Quick Reference

### Start System
```cmd
start_all.bat          # Windows
./start_all.sh         # Linux/macOS
```

### Access Points
- Dashboard: http://localhost:3001
- API: http://localhost:8000
- Docs: http://localhost:8000/docs
- Health: http://localhost:8000/health

### Test System
```bash
python quick_test.py
python test_intelliguard.py
```

### Stop System
```cmd
stop_all.bat           # Windows
Ctrl+C                 # Linux/macOS
```