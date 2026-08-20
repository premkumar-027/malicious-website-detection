import pandas as pd
import streamlit as st

from urllib.parse import urlparse

from src.feature_extractor import extract_url_features_v2
from src.predictor import load_model, predict_url


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Malicious Website Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# LOAD MODEL
# ============================================================

@st.cache_resource
def get_model():

    model, feature_names = load_model()

    return model, feature_names


model, feature_names = get_model()


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

    .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
        max-width: 1200px;
    }

    .main-title {
        font-size: 46px;
        font-weight: 800;
        text-align: center;
        margin-bottom: 5px;
    }

    .subtitle {
        text-align: center;
        color: #667085;
        font-size: 18px;
        margin-bottom: 30px;
    }

    .risk-high {
        padding: 25px;
        border-radius: 16px;
        background-color: #fff1f3;
        border: 1px solid #fecdca;
        text-align: center;
        margin: 20px 0;
    }

    .risk-low {
        padding: 25px;
        border-radius: 16px;
        background-color: #ecfdf3;
        border: 1px solid #abefc6;
        text-align: center;
        margin: 20px 0;
    }

    .risk-title {
        font-size: 28px;
        font-weight: 800;
    }

    .risk-description {
        font-size: 15px;
        margin-top: 8px;
        color: #475467;
    }

    .footer {
        text-align: center;
        color: #98a2b3;
        font-size: 13px;
        margin-top: 40px;
        padding: 20px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown("## 🛡️ MWD")

    st.caption(
        "Malicious Website Detector"
    )

    st.divider()

    page = st.radio(
        "Navigation",
        [
            "🏠 URL Detector",
            "📊 Model Dashboard",
            "ℹ️ About Project"
        ]
    )

    st.divider()

    st.markdown("### 🤖 Model")

    st.write(
        "Random Forest Classifier"
    )

    st.write(
        "33 URL Features"
    )

    st.write(
        "Binary Classification"
    )

    st.divider()

    st.caption(
        "End-to-End Machine Learning Project"
    )


# ============================================================
# PAGE 1 — URL DETECTOR
# ============================================================

if page == "🏠 URL Detector":

    # --------------------------------------------------------
    # Header
    # --------------------------------------------------------

    st.markdown(
        '<div class="main-title">'
        '🛡️ Malicious Website Detector'
        '</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="subtitle">'
        'Machine Learning powered phishing URL analysis'
        '</div>',
        unsafe_allow_html=True
    )

    # --------------------------------------------------------
    # How it works
    # --------------------------------------------------------

    st.info(
        """
        🔎 **How it works**

        Enter a website URL. The application extracts
        33 URL-based characteristics and uses a trained
        Random Forest classifier to estimate whether the
        URL resembles phishing or legitimate URLs in the
        training data.
        """
    )

    # --------------------------------------------------------
    # Security warning
    # --------------------------------------------------------

    st.warning(
        """
        ⚠️ **Security notice:** This is a machine-learning
        demonstration, not a security guarantee. Never enter
        passwords, payment information, or other sensitive
        information into a suspicious website.
        """
    )

    # --------------------------------------------------------
    # URL input
    # --------------------------------------------------------

    st.subheader(
        "🔗 Analyze Website"
    )

    url = st.text_input(
        "Enter URL",
        placeholder="https://example.com",
        help=(
            "Enter a complete URL including "
            "http:// or https://"
        )
    )

    analyze_button = st.button(
        "🔍 Analyze URL",
        type="primary",
        use_container_width=True
    )

    # ========================================================
    # ANALYZE URL
    # ========================================================

    if analyze_button:

        cleaned_url = url.strip()

        # ----------------------------------------------------
        # Empty URL validation
        # ----------------------------------------------------

        if not cleaned_url:

            st.error(
                "Please enter a URL."
            )

            st.stop()

        # ----------------------------------------------------
        # Protocol validation
        # ----------------------------------------------------

        if not cleaned_url.startswith(
            ("http://", "https://")
        ):

            st.error(
                "Please enter a complete URL beginning "
                "with http:// or https://"
            )

            st.stop()

        try:

            # ------------------------------------------------
            # Feature extraction
            # ------------------------------------------------

            features = extract_url_features_v2(
                cleaned_url
            )

            # ------------------------------------------------
            # Prediction
            # ------------------------------------------------

            prediction, probabilities, feature_df = (
                predict_url(
                    features,
                    model,
                    feature_names
                )
            )

            phishing_probability = (
                probabilities[0]
            )

            legitimate_probability = (
                probabilities[1]
            )

            # ------------------------------------------------
            # Parse URL
            # ------------------------------------------------

            parsed = urlparse(
                cleaned_url
            )

            domain = parsed.netloc

            path = parsed.path

            # ------------------------------------------------
            # Result
            # ------------------------------------------------

            st.divider()

            if prediction == 0:

                confidence = (
                    phishing_probability
                )

                risk_score = (
                    phishing_probability * 100
                )

                st.markdown(
                    """
                    <div class="risk-high">

                    <div class="risk-title">
                    🔴 Potentially Phishing Website
                    </div>

                    <div class="risk-description">
                    The URL contains characteristics that
                    resemble phishing URLs in the training data.
                    </div>

                    </div>
                    """,
                    unsafe_allow_html=True
                )

            else:

                confidence = (
                    legitimate_probability
                )

                risk_score = (
                    phishing_probability * 100
                )

                st.markdown(
                    """
                    <div class="risk-low">

                    <div class="risk-title">
                    🟢 Likely Legitimate Website
                    </div>

                    <div class="risk-description">
                    The URL appears more similar to legitimate
                    URLs according to the trained model.
                    </div>

                    </div>
                    """,
                    unsafe_allow_html=True
                )

            # ------------------------------------------------
            # Main metrics
            # ------------------------------------------------

            col1, col2, col3, col4 = (
                st.columns(4)
            )

            with col1:

                st.metric(
                    "Model Confidence",
                    f"{confidence * 100:.2f}%"
                )

            with col2:

                st.metric(
                    "Risk Score",
                    f"{risk_score:.2f}%"
                )

            with col3:

                st.metric(
                    "Features Analyzed",
                    len(feature_names)
                )

            with col4:

                st.metric(
                    "Protocol",
                    parsed.scheme.upper()
                )

            # ------------------------------------------------
            # Probability chart
            # ------------------------------------------------

            st.subheader(
                "📊 Prediction Probability"
            )

            probability_df = pd.DataFrame(
                {
                    "Class": [
                        "Phishing",
                        "Legitimate"
                    ],
                    "Probability": [
                        phishing_probability,
                        legitimate_probability
                    ]
                }
            )

            st.bar_chart(
                probability_df.set_index(
                    "Class"
                ),
                height=250
            )

            # ------------------------------------------------
            # URL analysis
            # ------------------------------------------------

            st.subheader(
                "🌐 URL Analysis"
            )

            info1, info2, info3, info4 = (
                st.columns(4)
            )

            with info1:

                st.metric(
                    "URL Length",
                    len(cleaned_url)
                )

            with info2:

                st.metric(
                    "Domain Length",
                    len(domain)
                )

            with info3:

                st.metric(
                    "Path Length",
                    len(path)
                )

            with info4:

                st.metric(
                    "Subdomains",
                    features[
                        "num_subdomains"
                    ]
                )

            # ------------------------------------------------
            # Security indicators
            # ------------------------------------------------

            st.subheader(
                "🔐 Security Indicators"
            )

            sec1, sec2, sec3, sec4 = (
                st.columns(4)
            )

            with sec1:

                if features["is_https"]:

                    st.success(
                        "🔒 HTTPS Enabled"
                    )

                else:

                    st.error(
                        "🔓 HTTPS Not Used"
                    )

            with sec2:

                if features["has_ip"]:

                    st.warning(
                        "🌐 IP Address Used"
                    )

                else:

                    st.success(
                        "🌐 Domain Used"
                    )

            with sec3:

                if features[
                    "has_suspicious_keyword"
                ]:

                    st.warning(
                        "⚠️ Suspicious Keyword"
                    )

                else:

                    st.success(
                        "✓ No Keyword Detected"
                    )

            with sec4:

                if features[
                    "domain_has_hyphen"
                ]:

                    st.warning(
                        "⚠️ Domain Has Hyphen"
                    )

                else:

                    st.success(
                        "✓ Domain Structure Normal"
                    )

            # ------------------------------------------------
            # URL details
            # ------------------------------------------------

            with st.expander(
                "🌐 View URL Details"
            ):

                st.write(
                    "**Complete URL:**"
                )

                st.code(
                    cleaned_url
                )

                st.write(
                    "**Domain:**",
                    domain
                )

                st.write(
                    "**Path:**",
                    path if path else "/"
                )

                st.write(
                    "**Query:**",
                    parsed.query
                    if parsed.query
                    else "None"
                )

                st.write(
                    "**Fragment:**",
                    parsed.fragment
                    if parsed.fragment
                    else "None"
                )

            # ------------------------------------------------
            # All features
            # ------------------------------------------------

            with st.expander(
                "🔬 View all 33 extracted features"
            ):

                feature_display = (
                    feature_df.T.rename(
                        columns={
                            0: "Value"
                        }
                    )
                )

                st.dataframe(
                    feature_display,
                    use_container_width=True
                )

            # ------------------------------------------------
            # Model information
            # ------------------------------------------------

            with st.expander(
                "🤖 Model Information"
            ):

                model_col1, model_col2 = (
                    st.columns(2)
                )

                with model_col1:

                    st.write(
                        "**Algorithm**"
                    )

                    st.write(
                        "Random Forest Classifier"
                    )

                    st.write(
                        "**Feature Count**"
                    )

                    st.write(
                        f"{len(feature_names)} URL features"
                    )

                with model_col2:

                    st.write(
                        "**Task**"
                    )

                    st.write(
                        "Binary Classification"
                    )

                    st.write(
                        "**Classes**"
                    )

                    st.write(
                        "0 = Phishing | "
                        "1 = Legitimate"
                    )

        except Exception as e:

            st.error(
                f"Unable to analyze URL: {e}"
            )


# ============================================================
# PAGE 2 — MODEL DASHBOARD
# ============================================================

elif page == "📊 Model Dashboard":

    st.title(
        "📊 Model Performance Dashboard"
    )

    st.write(
        "Performance of the URL-only "
        "Random Forest V2 model."
    )

    st.divider()

    # --------------------------------------------------------
    # Performance metrics
    # --------------------------------------------------------

    st.subheader(
        "🏆 Model Performance"
    )

    metric1, metric2, metric3, metric4 = (
        st.columns(4)
    )

    with metric1:

        st.metric(
            "Accuracy",
            "99.58%"
        )

    with metric2:

        st.metric(
            "Precision",
            "99.88%"
        )

    with metric3:

        st.metric(
            "Recall",
            "99.13%"
        )

    with metric4:

        st.metric(
            "F1 Score",
            "99.51%"
        )

    st.divider()

    # --------------------------------------------------------
    # Confusion Matrix
    # --------------------------------------------------------

    st.subheader(
        "🎯 Confusion Matrix"
    )

    confusion_data = pd.DataFrame(
        {
            "Predicted Phishing": [
                19930,
                24
            ],
            "Predicted Legitimate": [
                174,
                26946
            ]
        },
        index=[
            "Actual Phishing",
            "Actual Legitimate"
        ]
    )

    st.dataframe(
        confusion_data,
        use_container_width=True
    )

    st.caption(
        "Phishing = class 0 | Legitimate = class 1"
    )

    st.divider()

    # --------------------------------------------------------
    # Feature importance
    # --------------------------------------------------------

    st.subheader(
        "🔍 Top URL Features"
    )

    importance_data = pd.DataFrame(
        {
            "Feature": [
                "is_https",
                "num_slashes",
                "path_length",
                "num_digits",
                "url_length",
                "domain_length",
                "num_letters",
                "num_hyphens",
                "num_subdomains",
                "num_dots"
            ],

            "Importance": [
                0.441690,
                0.210272,
                0.148936,
                0.074092,
                0.050252,
                0.020131,
                0.017007,
                0.014749,
                0.012732,
                0.008552
            ]
        }
    )

    st.bar_chart(
        importance_data.set_index(
            "Feature"
        ),
        height=450
    )

    st.divider()

    # --------------------------------------------------------
    # Model comparison
    # --------------------------------------------------------

    st.subheader(
        "⚖️ Model Comparison"
    )

    comparison = pd.DataFrame(
        {
            "Model": [
                "Logistic Regression V1",
                "Random Forest V1",
                "Random Forest V2"
            ],

            "Accuracy": [
                0.993075,
                0.995645,
                0.995794
            ],

            "Precision": [
                0.999344,
                0.998847,
                0.998797
            ],

            "Recall": [
                0.984431,
                0.990947,
                0.991345
            ],

            "F1": [
                0.991831,
                0.994881,
                0.995057
            ]
        }
    )

    comparison_display = (
        comparison.copy()
    )

    for column in [
        "Accuracy",
        "Precision",
        "Recall",
        "F1"
    ]:

        comparison_display[column] = (
            comparison_display[column] * 100
        ).round(3).astype(str) + "%"

    st.dataframe(
        comparison_display,
        use_container_width=True,
        hide_index=True
    )

    st.divider()

    # --------------------------------------------------------
    # Dataset information
    # --------------------------------------------------------

    st.subheader(
        "📚 Dataset Information"
    )

    data1, data2, data3 = (
        st.columns(3)
    )

    with data1:

        st.metric(
            "Total URLs",
            "235,370"
        )

    with data2:

        st.metric(
            "Phishing URLs",
            "100,520"
        )

    with data3:

        st.metric(
            "Legitimate URLs",
            "134,850"
        )


# ============================================================
# PAGE 3 — ABOUT PROJECT
# ============================================================

elif page == "ℹ️ About Project":

    st.title(
        "ℹ️ About the Project"
    )

    st.markdown(
        """
        ## 🛡️ Malicious Website Detection

        This is an end-to-end machine learning project
        for detecting potentially phishing URLs using
        URL-based characteristics.
        """
    )

    st.divider()

    # --------------------------------------------------------
    # Workflow
    # --------------------------------------------------------

    st.subheader(
        "🔄 Machine Learning Workflow"
    )

    workflow = [
        "1. Dataset loading",
        "2. Data cleaning",
        "3. Exploratory Data Analysis",
        "4. Feature engineering",
        "5. Train/test split",
        "6. Logistic Regression baseline",
        "7. Random Forest training",
        "8. Cross-validation",
        "9. Hyperparameter tuning",
        "10. URL-only feature engineering",
        "11. Model evaluation",
        "12. Model serialization",
        "13. Streamlit deployment"
    ]

    for step in workflow:

        st.write(
            step
        )

    st.divider()

    # --------------------------------------------------------
    # Technologies
    # --------------------------------------------------------

    st.subheader(
        "🧰 Technologies Used"
    )

    tech1, tech2, tech3 = (
        st.columns(3)
    )

    with tech1:

        st.markdown(
            """
            ### 🐍 Python

            - Pandas
            - NumPy
            - Regular Expressions
            - urllib
            """
        )

    with tech2:

        st.markdown(
            """
            ### 🤖 Machine Learning

            - Scikit-learn
            - Logistic Regression
            - Random Forest
            - Cross-validation
            """
        )

    with tech3:

        st.markdown(
            """
            ### 🚀 Deployment

            - Streamlit
            - Joblib
            - VS Code
            - Virtual Environment
            """
        )

    st.divider()

    # --------------------------------------------------------
    # Results
    # --------------------------------------------------------

    st.subheader(
        "📈 Final URL Model Results"
    )

    results = pd.DataFrame(
        {
            "Metric": [
                "Accuracy",
                "Phishing Precision",
                "Phishing Recall",
                "Phishing F1"
            ],

            "Score": [
                "99.58%",
                "99.88%",
                "99.13%",
                "99.51%"
            ]
        }
    )

    st.dataframe(
        results,
        use_container_width=True,
        hide_index=True
    )

    st.divider()

    # --------------------------------------------------------
    # Limitations
    # --------------------------------------------------------

    st.subheader(
        "⚠️ Model Limitations"
    )

    st.markdown(
        """
        This application performs **URL-based analysis only**.

        It currently does not:

        - Visit the website
        - Inspect webpage HTML
        - Analyze JavaScript
        - Check DNS records
        - Perform WHOIS analysis
        - Query external threat intelligence
        - Guarantee website safety

        Therefore, predictions should be treated as
        **machine-learning estimates and not security guarantees**.
        """
    )

    st.divider()

    # --------------------------------------------------------
    # Future improvements
    # --------------------------------------------------------

    st.subheader(
        "🚀 Future Improvements"
    )

    st.markdown(
        """
        Future versions could include:

        - DNS and WHOIS features
        - HTML-based features
        - Website content analysis
        - Domain reputation
        - Threat intelligence APIs
        - Character-level deep learning
        - Explainable AI
        - REST API deployment
        - Cloud deployment
        """
    )


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div class="footer">

    🛡️ Malicious Website Detection
    • Python
    • Scikit-learn
    • Random Forest
    • Streamlit

    </div>
    """,
    unsafe_allow_html=True
)