# 🛡️ Malicious Website Detection using Machine Learning

An end-to-end Data Science and Machine Learning project for detecting
potentially phishing URLs using URL-based characteristics and a
Random Forest classifier.

## 📌 Project Overview

This project analyzes URL characteristics and predicts whether a URL
is potentially phishing or legitimate.

The trained machine learning model is deployed through a Streamlit
web application.

## 🎯 Objective

The project covers the complete machine learning workflow:

1. Dataset loading
2. Data cleaning
3. Exploratory Data Analysis
4. Feature engineering
5. Train/test split
6. Logistic Regression baseline
7. Random Forest model
8. Cross-validation
9. Hyperparameter tuning
10. URL-only feature engineering
11. Model evaluation
12. Model serialization
13. Streamlit deployment

## 📊 Dataset

Total URLs:

**235,370**

Class distribution:

- Phishing: 100,520
- Legitimate: 134,850

## 🤖 Final Model

**Algorithm:** Random Forest Classifier

**Task:** Binary Classification

**Features:** 33 URL-based features

## 📈 Model Performance

| Metric | Score |
|---|---:|
| Accuracy | 99.58% |
| Phishing Precision | 99.88% |
| Phishing Recall | 99.13% |
| Phishing F1 | 99.51% |

## 🔬 URL Features

The model uses 33 URL-based features including:

- URL length
- Number of letters
- Number of digits
- Number of dots
- Number of hyphens
- Number of underscores
- Number of slashes
- Number of question marks
- Number of equal signs
- Number of special characters
- Digit ratio
- Letter ratio
- Special character ratio
- HTTPS indicator
- Domain length
- Domain dot count
- Domain hyphen indicator
- Domain digit indicator
- Path length
- Number of path segments
- Query length
- Query parameter count
- Fragment length
- Fragment indicator
- Number of subdomains
- IP address indicator
- Suspicious keyword count
- Suspicious keyword indicator

## 🖥️ Streamlit Application

The application provides:

- URL input
- Phishing/legitimate prediction
- Model confidence
- Risk score
- Prediction probability
- URL statistics
- Security indicators
- Extracted URL features
- Model performance dashboard
- Project information

## 📁 Project Structure

```text
malicious-website-detection/
│
├── app/
│   └── app.py
│
├── data/
│
├── models/
│   ├── url_phishing_random_forest_v2.pkl
│   └── url_feature_names_v2.pkl
│
├── notebooks/
│
├── src/
│   ├── __init__.py
│   ├── feature_extractor.py
│   └── predictor.py
│
├── .gitignore
├── README.md
└── requirements.txt