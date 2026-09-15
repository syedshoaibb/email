import os
import re
import joblib
import numpy as np
import pandas as pd

from urllib.parse import urlparse

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)

from xgboost import XGBClassifier


# ============================================================
# CONFIGURATION
# ============================================================

DATASET_DIR = "dataset"
MODEL_DIR = "training/models"

CEAS_FILE = "CEAS_08.csv"
SPAMASSASSIN_FILE = "SpamAssasin.csv"

OUTPUT_MODEL = os.path.join(
    MODEL_DIR,
    "xgboost_header_model_v3.pkl"
)

RANDOM_STATE = 42

# Prevent excessive RAM usage during development.
# Set to None later if you want to use all rows.
MAX_ROWS_PER_DATASET = 20000


# ============================================================
# DIRECTORY
# ============================================================

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)


# ============================================================
# TEXT HELPERS
# ============================================================

def safe_text(value):
    if pd.isna(value):
        return ""
    return str(value).strip()


def extract_email_domain(value):
    """
    Extract the domain from an email address.
    Example:
        person@gmail.com -> gmail.com
    """

    value = safe_text(value).lower()

    if not value:
        return ""

    if "@" in value:
        return value.rsplit("@", 1)[-1]

    return ""


def extract_local_part(value):
    """
    Extract local part from an email address.
    Example:
        person@gmail.com -> person
    """

    value = safe_text(value).lower()

    if not value or "@" not in value:
        return ""

    return value.rsplit("@", 1)[0]


def domain_has_digit(domain):
    return int(
        any(
            char.isdigit()
            for char in domain
        )
    )


def domain_special_count(domain):
    return sum(
        1
        for char in domain
        if char in "-_."
    )


def local_special_count(local_part):
    return sum(
        1
        for char in local_part
        if char in "._+-"
    )


def count_urls(text):
    text = safe_text(text)

    return len(
        re.findall(
            r"https?://\S+|www\.\S+",
            text,
            flags=re.IGNORECASE
        )
    )


def suspicious_subject_count(subject):
    """
    Subject-only security indicators.

    Subject is part of the email header,
    so these features remain in the header model.
    """

    subject = safe_text(subject).lower()

    suspicious_words = [
        "urgent",
        "verify",
        "verification",
        "account",
        "password",
        "login",
        "security",
        "alert",
        "suspended",
        "payment",
        "invoice",
        "bank",
        "confirm",
        "click",
        "reset",
        "warning",
        "immediately",
        "action required",
        "important",
    ]

    count = 0

    for word in suspicious_words:
        count += subject.count(word)

    return count


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def create_header_features(df):
    """
    Create lightweight header-only features.

    IMPORTANT:
    We do NOT use:
        - email body
        - body length
        - body words
        - body URLs

    We only use:
        - sender
        - receiver
        - subject
        - basic date presence
    """

    features = pd.DataFrame(
        index=df.index
    )

    # --------------------------------------------------------
    # Sender
    # --------------------------------------------------------

    sender = (
        df["sender"]
        .fillna("")
        .astype(str)
    )

    sender_domain = sender.apply(
        extract_email_domain
    )

    sender_local = sender.apply(
        extract_local_part
    )

    features["sender_exists"] = (
        sender.str.len() > 0
    ).astype(np.int8)

    features["sender_domain_length"] = (
        sender_domain.str.len()
        .clip(upper=255)
        .astype(np.int16)
    )

    features["sender_domain_has_digit"] = (
        sender_domain.apply(
            domain_has_digit
        )
        .astype(np.int8)
    )

    features["sender_domain_special_count"] = (
        sender_domain.apply(
            domain_special_count
        )
        .clip(upper=50)
        .astype(np.int8)
    )

    features["sender_local_length"] = (
        sender_local.str.len()
        .clip(upper=255)
        .astype(np.int16)
    )

    features["sender_local_special_count"] = (
        sender_local.apply(
            local_special_count
        )
        .clip(upper=50)
        .astype(np.int8)
    )

    # --------------------------------------------------------
    # Receiver
    # --------------------------------------------------------

    receiver = (
        df["receiver"]
        .fillna("")
        .astype(str)
    )

    receiver_domain = receiver.apply(
        extract_email_domain
    )

    receiver_local = receiver.apply(
        extract_local_part
    )

    features["receiver_exists"] = (
        receiver.str.len() > 0
    ).astype(np.int8)

    features["receiver_domain_length"] = (
        receiver_domain.str.len()
        .clip(upper=255)
        .astype(np.int16)
    )

    features["receiver_domain_has_digit"] = (
        receiver_domain.apply(
            domain_has_digit
        )
        .astype(np.int8)
    )

    features["receiver_domain_special_count"] = (
        receiver_domain.apply(
            domain_special_count
        )
        .clip(upper=50)
        .astype(np.int8)
    )

    features["receiver_local_length"] = (
        receiver_local.str.len()
        .clip(upper=255)
        .astype(np.int16)
    )

    features["receiver_local_special_count"] = (
        receiver_local.apply(
            local_special_count
        )
        .clip(upper=50)
        .astype(np.int8)
    )

    # --------------------------------------------------------
    # Sender / receiver relationship
    # --------------------------------------------------------

    features["same_domain"] = (
        (sender_domain != "") &
        (receiver_domain != "") &
        (sender_domain == receiver_domain)
    ).astype(np.int8)

    features["domain_mismatch"] = (
        (sender_domain != "") &
        (receiver_domain != "") &
        (sender_domain != receiver_domain)
    ).astype(np.int8)

    # --------------------------------------------------------
    # Subject
    # --------------------------------------------------------

    subject = (
        df["subject"]
        .fillna("")
        .astype(str)
    )

    features["subject_exists"] = (
        subject.str.len() > 0
    ).astype(np.int8)

    features["subject_length"] = (
        subject.str.len()
        .clip(upper=5000)
        .astype(np.int16)
    )

    features["subject_word_count"] = (
        subject
        .str.split()
        .str.len()
        .clip(upper=500)
        .astype(np.int16)
    )

    features["subject_url_count"] = (
        subject.apply(
            count_urls
        )
        .clip(upper=20)
        .astype(np.int8)
    )

    features["subject_suspicious_count"] = (
        subject.apply(
            suspicious_subject_count
        )
        .clip(upper=50)
        .astype(np.int8)
    )

    features["subject_exclamation_count"] = (
        subject
        .str.count("!")
        .clip(upper=50)
        .astype(np.int8)
    )

    features["subject_question_count"] = (
        subject
        .str.count(r"\?")
        .clip(upper=50)
        .astype(np.int8)
    )

    # --------------------------------------------------------
    # Date
    # --------------------------------------------------------

    # We intentionally only keep existence.
    # We do NOT use year/month/day/hour because those can
    # encode dataset-specific patterns.
    date = (
        df["date"]
        .fillna("")
        .astype(str)
    )

    features["date_exists"] = (
        date.str.len() > 0
    ).astype(np.int8)

    # --------------------------------------------------------
    # Cleanup
    # --------------------------------------------------------

    features = features.replace(
        [np.inf, -np.inf],
        0
    )

    features = features.fillna(0)

    return features.astype(
        np.float32
    )


# ============================================================
# LOAD DATASET
# ============================================================

def load_dataset(filename):

    path = os.path.join(
        DATASET_DIR,
        filename
    )

    if not os.path.exists(path):

        raise FileNotFoundError(
            f"\nDataset not found:\n{path}"
        )

    print(
        f"\nLoading: {filename}"
    )

    df = pd.read_csv(
        path,
        nrows=MAX_ROWS_PER_DATASET
    )

    required_columns = [
        "sender",
        "receiver",
        "date",
        "subject",
        "label",
    ]

    missing = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing:

        raise ValueError(
            f"\n{filename} is missing columns:\n"
            f"{missing}"
        )

    df = df[
        required_columns
    ].copy()

    # Convert labels
    df["label"] = pd.to_numeric(
        df["label"],
        errors="coerce"
    )

    df = df.dropna(
        subset=["label"]
    )

    df["label"] = (
        df["label"]
        .astype(int)
    )

    # Keep binary classification only
    df = df[
        df["label"].isin([0, 1])
    ].copy()

    print(
        f"Rows loaded: {len(df):,}"
    )

    print(
        "Label distribution:"
    )

    print(
        df["label"]
        .value_counts()
        .sort_index()
        .to_dict()
    )

    # Make sure both classes exist
    classes = set(
        df["label"].unique()
    )

    if classes != {0, 1}:

        raise ValueError(
            f"\n{filename} does not contain "
            f"both classes 0 and 1.\n"
            f"Found: {classes}"
        )

    return df


# ============================================================
# BALANCE DATASET
# ============================================================

def balance_dataset(
    df,
    dataset_name
):
    """
    Downsample the larger class so that both classes
    contain the same number of records.
    """

    class_0 = df[
        df["label"] == 0
    ]

    class_1 = df[
        df["label"] == 1
    ]

    target_size = min(
        len(class_0),
        len(class_1)
    )

    class_0 = class_0.sample(
        n=target_size,
        random_state=RANDOM_STATE
    )

    class_1 = class_1.sample(
        n=target_size,
        random_state=RANDOM_STATE
    )

    balanced = pd.concat(
        [
            class_0,
            class_1
        ],
        ignore_index=True
    )

    balanced = balanced.sample(
        frac=1.0,
        random_state=RANDOM_STATE
    ).reset_index(
        drop=True
    )

    print(
        f"\nBalanced {dataset_name}:"
    )

    print(
        balanced["label"]
        .value_counts()
        .sort_index()
        .to_dict()
    )

    return balanced


# ============================================================
# TRAIN XGBOOST
# ============================================================

def build_model():

    return XGBClassifier(
        n_estimators=250,
        max_depth=5,
        learning_rate=0.05,
        subsample=0.80,
        colsample_bytree=0.80,
        min_child_weight=3,
        gamma=0.10,
        reg_alpha=0.10,
        reg_lambda=1.50,

        objective="binary:logistic",

        eval_metric="logloss",

        tree_method="hist",

        n_jobs=2,

        random_state=RANDOM_STATE
    )


# ============================================================
# EVALUATION
# ============================================================

def evaluate_model(
    model,
    X_test,
    y_test,
    title
):

    probabilities = model.predict_proba(
        X_test
    )[:, 1]

    predictions = (
        probabilities >= 0.50
    ).astype(int)

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    try:
        roc_auc = roc_auc_score(
            y_test,
            probabilities
        )
    except Exception:

        roc_auc = 0.0

    matrix = confusion_matrix(
        y_test,
        predictions
    )

    print("\n")
    print("=" * 70)
    print(title)
    print("=" * 70)

    print(
        f"Accuracy : {accuracy:.4f}"
    )

    print(
        f"Precision: {precision:.4f}"
    )

    print(
        f"Recall   : {recall:.4f}"
    )

    print(
        f"F1 Score : {f1:.4f}"
    )

    print(
        f"ROC-AUC  : {roc_auc:.4f}"
    )

    print("\nConfusion Matrix:")

    print(matrix)

    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            predictions,
            digits=4,
            zero_division=0
        )
    )

    return {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "roc_auc": float(roc_auc),
    }


# ============================================================
# CROSS DATASET TEST
# ============================================================

def cross_dataset_test(
    train_df,
    test_df,
    train_name,
    test_name
):

    print("\n")
    print("=" * 70)
    print(
        f"CROSS-DATASET TEST"
    )
    print(
        f"Train: {train_name}"
    )
    print(
        f"Test : {test_name}"
    )
    print("=" * 70)

    X_train = create_header_features(
        train_df
    )

    y_train = train_df["label"].astype(
        np.int8
    )

    X_test = create_header_features(
        test_df
    )

    y_test = test_df["label"].astype(
        np.int8
    )

    X_test = X_test.reindex(
        columns=X_train.columns,
        fill_value=0
    )

    print(
        f"\nTraining shape: {X_train.shape}"
    )

    print(
        f"Testing shape : {X_test.shape}"
    )

    model = build_model()

    model.fit(
        X_train,
        y_train
    )

    return evaluate_model(
        model,
        X_test,
        y_test,
        f"{train_name} -> {test_name}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print("\n")
    print("=" * 70)
    print(
        "M1 HEADER THREAT DETECTOR - XGBOOST V3"
    )
    print("=" * 70)

    print(
        "\nTraining sources:"
    )

    print(
        "  1. CEAS_08.csv"
    )

    print(
        "  2. SpamAssasin.csv"
    )

    print(
        "\nExcluded from this version:"
    )

    print(
        "  Nazario.csv"
    )

    print(
        "  Nigerian_Fraud.csv"
    )

    print(
        "\nReason:"
    )

    print(
        "Avoid single-class/source-specific bias "
        "during the initial model."
    )

    # ========================================================
    # LOAD
    # ========================================================

    ceas = load_dataset(
        CEAS_FILE
    )

    spamassassin = load_dataset(
        SPAMASSASSIN_FILE
    )

    # ========================================================
    # BALANCE INDIVIDUAL SOURCES
    # ========================================================

    ceas_balanced = balance_dataset(
        ceas,
        "CEAS_08"
    )

    spamassassin_balanced = balance_dataset(
        spamassassin,
        "SpamAssasin"
    )

    # ========================================================
    # CROSS-DATASET VALIDATION
    # ========================================================

    results_ceas_to_spam = cross_dataset_test(
        ceas_balanced,
        spamassassin_balanced,
        "CEAS_08",
        "SpamAssasin"
    )

    results_spam_to_ceas = cross_dataset_test(
        spamassassin_balanced,
        ceas_balanced,
        "SpamAssasin",
        "CEAS_08"
    )

    # ========================================================
    # NORMAL STRATIFIED VALIDATION
    # ========================================================

    combined = pd.concat(
        [
            ceas_balanced,
            spamassassin_balanced
        ],
        ignore_index=True
    )

    combined = combined.sample(
        frac=1.0,
        random_state=RANDOM_STATE
    ).reset_index(
        drop=True
    )

    print("\n")
    print("=" * 70)
    print(
        "COMBINED DATASET"
    )
    print("=" * 70)

    print(
        f"Rows: {len(combined):,}"
    )

    print(
        combined["label"]
        .value_counts()
        .sort_index()
        .to_dict()
    )

    X = create_header_features(
        combined
    )

    y = combined["label"].astype(
        np.int8
    )

    X_train, X_test, y_train, y_test = (
        train_test_split(
            X,
            y,
            test_size=0.20,
            random_state=RANDOM_STATE,
            stratify=y
        )
    )

    print(
        f"\nTrain shape: {X_train.shape}"
    )

    print(
        f"Test shape : {X_test.shape}"
    )

    model = build_model()

    print(
        "\nTraining combined model..."
    )

    model.fit(
        X_train,
        y_train
    )

    combined_results = evaluate_model(
        model,
        X_test,
        y_test,
        "COMBINED CEAS + SPAMASSASSIN"
    )

    # ========================================================
    # FEATURE IMPORTANCE
    # ========================================================

    importance = pd.DataFrame(
        {
            "feature": X.columns,
            "importance": model.feature_importances_
        }
    ).sort_values(
        "importance",
        ascending=False
    )

    print("\n")
    print("=" * 70)
    print(
        "TOP FEATURE IMPORTANCE"
    )
    print("=" * 70)

    print(
        importance.head(15).to_string(
            index=False
        )
    )

    # ========================================================
    # SAVE FINAL MODEL
    # ========================================================

    model_package = {
        "model": model,

        "feature_names": list(
            X.columns
        ),

        "model_type": (
            "XGBoost Header Threat Detector V3"
        ),

        "training_datasets": [
            CEAS_FILE,
            SPAMASSASSIN_FILE
        ],

        "excluded_datasets": [
            "Nazario.csv",
            "Nigerian_Fraud.csv"
        ],

        "label_meaning": {
            "0": "class_0",
            "1": "class_1"
        },

        "metrics": {
            "combined_test": combined_results,

            "ceas_to_spamassassin":
                results_ceas_to_spam,

            "spamassassin_to_ceas":
                results_spam_to_ceas,
        }
    }

    joblib.dump(
        model_package,
        OUTPUT_MODEL
    )

    print("\n")
    print("=" * 70)
    print(
        "FINAL MODEL SAVED"
    )
    print("=" * 70)

    print(
        os.path.abspath(
            OUTPUT_MODEL
        )
    )

    print("\nTraining finished successfully.")


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()