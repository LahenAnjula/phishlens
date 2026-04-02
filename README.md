# 🔐 PHISHLENS – Phishing Detection System 

PHISHLENS is a hybrid phishing detection system that combines Machine Learning and Deep Learning (CNN) with Explainable AI (XAI) to detect malicious URLs in real-time. The system is designed to be lightweight, efficient, and suitable for browser-based environments.

## 🚀 Features 
- Real-time phishing URL detection
- Hybrid model (ML + CNN) for improved accuracy
- Explainable AI (SHAP) for transparent predictions
- Low latency and efficient performance
- Adversarial robustness against obfuscated URLs
- Privacy-focused (no external API dependency)

## 📋 Requirements 
- Python 3.10+
- FastAPI
- TensorFlow / Keras
- NumPy
- Pandas
- SHAP
- Uvicorn

## ⚙️ Installation 
1. Clone the repository:
bash
git clone https://github.com/LahenAnjula/phishlens.git
cd phishlens
2. Install dependencies:
bash
pip install -r requirements.txt
3. Run the application:
bash
uvicorn app:app --reload

## ▶️ Usage 
- Open your browser and go to:
http://127.0.0.1:8000
- Enter a URL to check whether it is **phishing or legitimate**
- View:
  - Prediction result
  - Risk score
  - Explainable reasons (XAI output)

## 📂 Project Structure
phishlens/
│
├── app.py
├── features.py
├── trusted_store.py
├── dynamic_trusted.json
│
├── static/
│   ├── app.js
│   └── style.css
│
├── templates/
│   └── index.html
│
├── .gitignore
└── README.md

## ⚠️ Note Model files (.pkl, .keras) are not included due to size limitations. They can be regenerated or provided separately if required. 

## 🙏 Acknowledgement 
This project was developed as part of a Final Year Research Project under the BSc (Hons) Computer Science degree programme at the University of Westminster. It focuses on cybersecurity, machine learning, and explainable AI for real-time phishing detection. --- ## 👨‍💻 Author **Lahen Anjula** BSc (Hons) Computer Science – University of Westminster Associate Software Engineer – HCLTech
