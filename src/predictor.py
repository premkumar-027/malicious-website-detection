import os

import joblib
import pandas as pd


# Project root
BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "url_phishing_random_forest_v2.pkl"
)


FEATURE_PATH = os.path.join(
    BASE_DIR,
    "models",
    "url_feature_names_v2.pkl"
)


def load_model():

    model = joblib.load(
        MODEL_PATH
    )

    feature_names = joblib.load(
        FEATURE_PATH
    )

    return model, feature_names


def predict_url(
    url_features,
    model,
    feature_names
):

    feature_df = pd.DataFrame(
        [url_features]
    )

    # Match training feature order
    feature_df = feature_df[
        feature_names
    ]

    prediction = model.predict(
        feature_df
    )[0]

    probabilities = model.predict_proba(
        feature_df
    )[0]

    return (
        prediction,
        probabilities,
        feature_df
    )