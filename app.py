from typing import List
import io
import re

import joblib
import pandas as pd
import numpy as np
from pydantic import BaseModel

from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences

import shap

from features import extract_features, extract_root_domain
from trusted_store import load_dynamic_trusted, save_dynamic_trusted

app = FastAPI(title="PhishLens Hybrid AI")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# ---------------- MODELS ----------------
tab_model = joblib.load("phish_model.pkl")
feature_names = joblib.load("feature_names.pkl")
tokenizer = joblib.load("url_tokenizer.pkl")
max_chars = joblib.load("max_chars.pkl")
fusion_config = joblib.load("hybrid_fusion_config.pkl")

deep_model = tf.keras.models.load_model("url_deep_model.keras")

# ---------------- SHAP XAI ----------------
xai_background = np.zeros((1, len(feature_names)))

def model_predict_for_shap(x):
    df = pd.DataFrame(x, columns=feature_names)
    return tab_model.predict_proba(df)[:, 1]

explainer = shap.KernelExplainer(model_predict_for_shap, xai_background)


class BatchRequest(BaseModel):
    urls: List[str]


# ---------------- UTILITIES ----------------
def normalize_url(url: str) -> str:
    url = str(url).strip().lower()
    url = url.replace(" ", "")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    url = re.sub(r"^(https?://)www\.", r"\1", url)
    return url


def prepare_features(features: dict) -> pd.DataFrame:
    feat = pd.DataFrame([features])
    feat = feat.apply(pd.to_numeric, errors="coerce").fillna(0)
    return feat[feature_names]


def prepare_text(url: str):
    seq = tokenizer.texts_to_sequences([url])
    return pad_sequences(seq, maxlen=max_chars, padding="post", truncating="post")


def get_risk_level(score: float) -> str:
    if score > 0.90:
        return "CRITICAL"
    elif score > 0.75:
        return "HIGH"
    elif score > 0.55:
        return "MEDIUM"
    return "LOW"


# ---------------- XAI FUNCTION ----------------
def get_xai_explanations(features_df):
    try:
        sample = features_df[feature_names].values.astype(float)
        shap_values = explainer.shap_values(sample, nsamples=50)

        if isinstance(shap_values, list):
            values = shap_values[0]
        else:
            values = shap_values

        if len(values.shape) == 2:
            values = values[0]

        pairs = list(zip(feature_names, values))
        pairs = sorted(pairs, key=lambda x: abs(x[1]), reverse=True)

        explanations = []
        for name, val in pairs[:5]:
            if val > 0:
                explanations.append(f"{name} increases phishing risk")
            else:
                explanations.append(f"{name} reduces phishing risk")

        return explanations

    except Exception as e:
        return [f"XAI unavailable: {str(e)}"]


# ---------------- ADVERSARIAL ROBUSTNESS ----------------
def adversarial_score(features: dict):
    score = 0.0
    reasons = []

    if features.get("impersonation_flag"):
        score += 0.4
        reasons.append("Possible domain impersonation detected.")

    if features.get("entropy", 0) > 3.8:
        score += 0.2
        reasons.append("High randomness detected in domain.")

    if features.get("subdomain_count", 0) > 2:
        score += 0.1
        reasons.append("Suspicious subdomain usage.")

    if features.get("digit_count", 0) > 2:
        score += 0.1
        reasons.append("Excessive digits in domain.")

    if features.get("hyphen_count", 0) > 1:
        score += 0.05
        reasons.append("Multiple hyphens detected.")

    if (
        features.get("has_login") or
        features.get("has_verify") or
        features.get("has_account")
    ):
        score += 0.15
        reasons.append("Credential-targeting keywords detected.")

    return min(score, 1.0), reasons


# ---------------- REPUTATION ----------------
def domain_reputation_score(features: dict) -> float:
    score = 0.5

    if features.get("trusted_domain"):
        score += 0.30
    if features.get("impersonation_flag"):
        score -= 0.50
    if features.get("rare_domain"):
        score -= 0.05
    if features.get("entropy", 0) > 3.5:
        score -= 0.10
    if features.get("has_https"):
        score += 0.05

    return max(0.0, min(1.0, score))


# ---------------- EXPLANATIONS ----------------
def generate_explanations(features, tab_score, text_score, rep_score, adv_score, final_score, adv_reasons, xai_reasons):
    explanations = []

    if features.get("trusted_domain"):
        explanations.append("Trusted domain detected.")

    if features.get("impersonation_flag"):
        explanations.append("Domain resembles a known trusted domain.")

    if features.get("rare_domain"):
        explanations.append("Uncommon domain detected.")

    if not features.get("has_https"):
        explanations.append("No HTTPS detected.")

    if features.get("entropy", 0) > 3.3:
        explanations.append("High randomness in domain.")

    explanations.extend(adv_reasons)
    explanations.extend(xai_reasons)

    explanations.append(
        f"Scores → Tabular: {tab_score:.3f}, Deep: {text_score:.3f}, Reputation: {rep_score:.3f}, Adversarial: {adv_score:.3f}, Final: {final_score:.3f}"
    )

    return explanations


# ---------------- TRUST UPDATE ----------------
def update_dynamic_trusted(url, prediction, final_score):
    root = extract_root_domain(url)
    trusted = load_dynamic_trusted()

    if prediction == "LEGIT" and final_score < 0.15:
        trusted.add(root)
        save_dynamic_trusted(trusted)


# ---------------- CORE LOGIC ----------------
def predict_url_logic(url: str):
    url = normalize_url(url)
    features = extract_features(url)

    feat = prepare_features(features)

    # XAI
    xai_reasons = get_xai_explanations(feat)

    # Tabular
    tab_score = float(tab_model.predict_proba(feat)[0][1])

    # Deep
    text_input = prepare_text(url)
    text_score = float(deep_model.predict(text_input, verbose=0).ravel()[0])

    # Reputation
    rep_score = domain_reputation_score(features)

    # Adversarial
    adv_score, adv_reasons = adversarial_score(features)

    # Hybrid
    hybrid_score = (
        fusion_config["tab_weight"] * tab_score +
        fusion_config["text_weight"] * text_score
    )

    final_score = (
        0.65 * hybrid_score +
        0.20 * (1 - rep_score) +
        0.15 * adv_score
    )

    # Decision
    if features.get("trusted_domain") and not features.get("impersonation_flag"):
        prediction = "LEGIT"
        final_score = min(final_score, 0.05)
    else:
        prediction = "PHISHING" if final_score > fusion_config["threshold"] else "LEGIT"

    reasons = generate_explanations(
        features, tab_score, text_score, rep_score, adv_score, final_score, adv_reasons, xai_reasons
    )

    update_dynamic_trusted(url, prediction, final_score)

    return {
        "url": url,
        "prediction": prediction,
        "risk_score": round(final_score, 3),
        "risk_level": get_risk_level(final_score),
        "tabular_score": round(tab_score, 3),
        "deep_score": round(text_score, 3),
        "reputation_score": round(rep_score, 3),
        "adversarial_score": round(adv_score, 3),
        "reasons": reasons
    }


# ---------------- ROUTES ----------------
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/predict")
def predict(url: str):
    try:
        return predict_url_logic(url)
    except Exception as e:
        return {"error": str(e)}


@app.get("/health")
def health():
    return {"status": "PhishLens API Running"}


@app.post("/batch")
async def batch_predict(payload: BatchRequest):
    try:
        return {
            "results": [predict_url_logic(u) for u in payload.urls if str(u).strip()]
        }
    except Exception as e:
        return {"error": str(e)}


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    try:
        content = await file.read()
        df = pd.read_csv(io.BytesIO(content))

        if "url" not in df.columns:
            return {"error": "CSV must contain 'url' column"}

        results = [predict_url_logic(u) for u in df["url"].dropna().astype(str)]
        return {"results": results}
    except Exception as e:
        return {"error": str(e)}