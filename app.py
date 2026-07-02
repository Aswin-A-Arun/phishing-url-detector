import streamlit as st
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier as RF
from sklearn.metrics import accuracy_score
from xgboost import XGBClassifier as xgb

from llm_integration import explain_url
from features import clean_url, extract_features

from urllib.parse import urlparse
import re
import tldextract

st.title("Phishing URL Detector")
st.caption(
    "Analyzes URL structure, suspicious keywords, domain reputation, and phishing indicators."
)


@st.cache_resource
def train_model():

    data = pd.read_csv("phishing2.csv")
    data["url"] = data["url"].apply(clean_url)

    data = data.dropna(subset=["url"])

    X = pd.DataFrame(
        data["url"].apply(extract_features).tolist()
    )

    y = data["status"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42
    )

    model = RF(
        n_estimators=100,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train, y_train)
    importance = pd.DataFrame({
        "Feature": X.columns,
        "Importance": model.feature_importances_
    })

    importance = importance.sort_values(
        by="Importance",
        ascending=False
    )

    model_xgb = xgb(
        n_estimators = 100,
        random_state = 42,
        n_jobs=-1,
        tree_method="hist"
    )

    model_xgb.fit(X_train, y_train)
    importance_xgb = pd.DataFrame({
        "Feature": X.columns,
        "Importance": model_xgb.feature_importances_
    })

    importance_xgb = importance_xgb.sort_values(
        by="Importance",
        ascending=False
    )

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    xgb_y_pred = model_xgb.predict(X_test)
    accuracy_xgb = accuracy_score(y_test, xgb_y_pred)

    return model, accuracy, importance, len(data), model_xgb, accuracy_xgb, importance_xgb

model, accuracy, importance, dataset_size, model_xgb, accuracy_xgb, importance_xgb = train_model()


st.sidebar.metric(
    "Dataset Size",
    f"{dataset_size:,}"
)

st.sidebar.metric(
    "Model Used",
    f"XGBoost"
)

st.sidebar.metric(
    "XGB Accuracy",
    f"{accuracy_xgb:.2%}"
)

st.sidebar.metric(
    "RF Accuracy",
    f"{accuracy:.2%}"
)

# with st.sidebar.expander("XGBoost Features"):
#     st.dataframe(importance_xgb.head(10))

# with st.sidebar.expander("Random Forest Features"):
#     st.dataframe(importance.head(10))


url = st.text_input("Enter Website URL")

if st.button("Analyze"):

    if url.strip() == "":
        st.warning("Please enter a URL")
    else:
        features = pd.DataFrame(
            [extract_features(url)]
        )
        # st.write(features.T)
        prediction = model.predict(features)[0]
        prediction_xgb = model_xgb.predict(features)[0]
        confidence = max(
            model.predict_proba(features)[0]
        ) * 100

        confidence_xgb = max(
            model_xgb.predict_proba(features)[0]
        ) * 100


        st.subheader("Final Verdict (XGBoost)")

        if confidence_xgb > 90:
            st.progress(1.0)

        elif confidence_xgb > 70:
            st.progress(0.7)

        else:
            st.progress(0.5)
        
        if prediction_xgb == 0:
            st.error(
                f"⚠️ Phishing Website Detected ({confidence_xgb:.2f}%)"
            )
        else:
            st.success(
                f"✅ Legitimate Website ({confidence_xgb:.2f}%)"
            )

        triggered = []
        if features["contains_sus_tld"][0]:
            triggered.append("⚠️ Suspicious TLD detected")

        if features["brand_in_subdomain"][0]:
            triggered.append("⚠️ Brand name found in subdomain")

        if features["suspicious_keyword_count"][0] > 0:
            triggered.append(
                f"⚠️ {features['suspicious_keyword_count'][0]} suspicious keywords found"
            )

        if not features["known_domain"][0]:
            triggered.append(
                "⚠️ Domain not in trusted domain list"
            )


        positive = []
        if features["known_domain"][0]:
            positive.append("Known trusted domain")

        if features["suspicious_keyword_count"][0] == 0:
            positive.append("No suspicious keywords detected")

        if not features["contains_sus_tld"][0]:
            positive.append("No suspicious TLD detected")
        try:

        
            analysis = explain_url(
                url,
                "Phishing" if prediction_xgb == 0 else "Legitimate",
                confidence_xgb,
                triggered,
                positive
            )
        except Exception:
            analysis = (
                "AI Explanation unavailable"
                "Showing only model prediction."
            )

        st.subheader("🧠 AI Analysis")
        st.write(analysis)

        st.divider()
        # st.subheader("Model Comparison")
        with st.expander("Model Comparison"):
            col1, col2 = st.columns(2)
            with col1:
                with st.container(border=True):
                    st.subheader("XGBoost")
                    if prediction_xgb == 0:
                        st.error(
                            f"⚠️ High Risk URL ({confidence_xgb:.1f}%)"
                        )
                    else:
                        st.success(
                            f"✅ Likely Legitimate ({confidence_xgb:.1f}%)"
                        )
                    st.write(f"Confidence: {confidence_xgb:.2f}%")
                    for _, row in importance.head(5).iterrows():
                        st.write(
                            f"• {row['Feature']} ({row['Importance']:.3f})"
                        )

            with col2:
                with st.container(border=True):
                    st.subheader("Random Forest")

                    if prediction == 0:
                        st.error("⚠️ Phishing Website Detected")
                    else:
                        st.success("✅ Legitimate Website")

                    st.write(f"Confidence: {confidence:.2f}%")

                    for _, row in importance_xgb.head(5).iterrows():
                        st.write(
                            f"• {row['Feature']} ({row['Importance']:.3f})"
                        )