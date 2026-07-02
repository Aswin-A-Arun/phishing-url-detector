# Phishing Website Detector

A machine learning-based phishing URL detector built using Streamlit, Random Forest, XGBoost, and Groq LLM integration.

## Features

- URL-based phishing detection
- Feature engineering using domain and URL characteristics
- Random Forest and XGBoost models (Final verdict: XGBoost)
- Known-domain reputation checking
- Suspicious keyword detection
- Suspicious TLD detection
- AI-generated explanations using Groq API's

## Dataset

- ~822,000 URLs
- Legitimate and phishing website samples

## Technologies Used

- Python
- Streamlit
- Pandas
- Scikit-learn
- XGBoost
- tldextract
- Groq API

## Installation

Clone the repository:

```bash
git clone <repo-url>
cd phishing-website-detector
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

Before running the application, open `llm_integration.py` and replace:

```python
GROQ_API_KEY=your_api_key_here
```
With your Groq API key.

## Usage
Navigate to the project directory and run:

```bash
streamlit run app.py
```

## Project Structure

```text
app.py                # Streamlit UI and model training
features.py           # URL cleaning and feature extraction
llm_integration.py    # Groq-based AI explanations
phishing2.csv         # Dataset
```

## Results

| Model | Accuracy |
|---------|---------:|
| Random Forest | 92.11% |
| XGBoost | 90.63% |

Although Random Forest achieved slightly higher accuracy, XGBoost produced correct/reliable real-world predictions during testing and is used as the primary verdict model.

## Future Improvements (Not set in stone yet)

- Domain age and WHOIS checks
- Certificate analysis
- DNS reputation checks
- VirusTotal integration
- Deep learning based URL classification

