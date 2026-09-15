import os
import joblib
import numpy as np

from email import policy
from email.parser import BytesParser

from training.train_header_model import create_header_features

from m1_rules import analyze_content

from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
)

import torch


# ============================================================
# PATHS
# ============================================================

HEADER_MODEL_PATH = (
    "training/models/xgboost_header_model_v3.pkl"
)

TEXT_MODEL_PATH = (
    "training/models/distilroberta_email_model"
)


# ============================================================
# LOAD MODELS
# ============================================================

print("Loading XGBoost header model...")

header_package = joblib.load(
    HEADER_MODEL_PATH
)

header_model = header_package["model"]

header_feature_names = (
    header_package["feature_names"]
)


print("Loading DistilRoBERTa...")

tokenizer = AutoTokenizer.from_pretrained(
    TEXT_MODEL_PATH
)

text_model = AutoModelForSequenceClassification.from_pretrained(
    TEXT_MODEL_PATH
)

text_model.eval()


# ============================================================
# EMAIL PARSING
# ============================================================

def parse_eml(eml_path):

    if not os.path.exists(eml_path):
        raise FileNotFoundError(
            f"Email file not found: {eml_path}"
        )

    with open(
        eml_path,
        "rb"
    ) as file:

        message = BytesParser(
            policy=policy.default
        ).parse(file)

    sender = message.get(
        "From",
        ""
    )

    receiver = message.get(
        "To",
        ""
    )

    date = message.get(
        "Date",
        ""
    )

    subject = message.get(
        "Subject",
        ""
    )

    # --------------------------------------------------------
    # Body
    # --------------------------------------------------------

    body_parts = []

    if message.is_multipart():

        for part in message.walk():

            content_type = (
                part.get_content_type()
            )

            if content_type in [
                "text/plain",
                "text/html",
            ]:

                try:

                    content = part.get_content()

                    if content:
                        body_parts.append(
                            str(content)
                        )

                except Exception:
                    pass

    else:

        try:

            content = message.get_content()

            if content:
                body_parts.append(
                    str(content)
                )

        except Exception:
            pass

    body = "\n".join(
        body_parts
    )

    return {
        "sender": sender,
        "receiver": receiver,
        "date": date,
        "subject": subject,
        "body": body,
    }


# ============================================================
# HEADER MODEL
# ============================================================

def run_header_model(email_data):

    import pandas as pd

    df = pd.DataFrame(
        [
            {
                "sender":
                    email_data["sender"],

                "receiver":
                    email_data["receiver"],

                "date":
                    email_data["date"],

                "subject":
                    email_data["subject"],

                # Required by feature function,
                # but deliberately not used.
                "label": 0,
            }
        ]
    )

    features = create_header_features(
        df
    )

    features = features.reindex(
        columns=header_feature_names,
        fill_value=0
    )

    probability = float(
        header_model.predict_proba(
            features
        )[0][1]
    )

    prediction = int(
        probability >= 0.50
    )

    return {
        "prediction": prediction,
        "class_1_probability": round(
            probability,
            4
        ),
        "class_0_probability": round(
            1.0 - probability,
            4
        ),
    }


# ============================================================
# TEXT MODEL
# ============================================================

def run_text_model(
    subject,
    body
):

    combined_text = (
        subject
        + "\n\n"
        + body
    )

    inputs = tokenizer(
        combined_text,
        return_tensors="pt",
        truncation=True,
        padding=True,
        max_length=128,
    )

    with torch.no_grad():

        outputs = text_model(
            **inputs
        )

    probabilities = torch.softmax(
        outputs.logits,
        dim=1
    )[0].cpu().numpy()

    prediction = int(
        np.argmax(
            probabilities
        )
    )

    return {
        "prediction": prediction,
        "class_0_probability": round(
            float(probabilities[0]),
            4
        ),
        "class_1_probability": round(
            float(probabilities[1]),
            4
        ),
    }


# ============================================================
# COMBINE RESULTS
# ============================================================

def combine_results(
    header_result,
    text_result,
    rule_result
):

    header_score = (
        header_result[
            "class_1_probability"
        ]
    )

    text_score = (
        text_result[
            "class_1_probability"
        ]
    )

    rule_score = (
        rule_result[
            "rule_score"
        ] / 100.0
    )

    # --------------------------------------------------------
    # Prototype fusion
    # --------------------------------------------------------
    #
    # Header       30%
    # Text         50%
    # Rules        20%
    #
    # M2/M3/M4 will later replace this simple
    # prototype fusion.
    # --------------------------------------------------------

    final_score = (
        (0.30 * header_score)
        +
        (0.50 * text_score)
        +
        (0.20 * rule_score)
    )

    final_score = max(
        0.0,
        min(
            1.0,
            final_score
        )
    )

    if final_score >= 0.75:

        verdict = "HIGH_RISK"

    elif final_score >= 0.50:

        verdict = "SUSPICIOUS"

    else:

        verdict = "LOW_RISK"

    return {
        "final_score": round(
            final_score,
            4
        ),

        "final_percentage": round(
            final_score * 100,
            2
        ),

        "verdict": verdict,
    }


# ============================================================
# MAIN ANALYSIS
# ============================================================

def analyze_eml(
    eml_path
):

    print("\n")
    print("=" * 70)
    print("M1 EMAIL THREAT DETECTION")
    print("=" * 70)

    # --------------------------------------------------------
    # Parse email
    # --------------------------------------------------------

    email_data = parse_eml(
        eml_path
    )

    print(
        f"\nSubject: {email_data['subject']}"
    )

    # --------------------------------------------------------
    # Header model
    # --------------------------------------------------------

    print(
        "\nRunning header XGBoost..."
    )

    header_result = run_header_model(
        email_data
    )

    # --------------------------------------------------------
    # Text model
    # --------------------------------------------------------

    print(
        "Running DistilRoBERTa..."
    )

    text_result = run_text_model(
        email_data["subject"],
        email_data["body"]
    )

    # --------------------------------------------------------
    # Rules
    # --------------------------------------------------------

    print(
        "Running content rules..."
    )

    rule_result = analyze_content(
        subject=email_data["subject"],
        body=email_data["body"]
    )

    # --------------------------------------------------------
    # Fusion
    # --------------------------------------------------------

    combined_result = combine_results(
        header_result,
        text_result,
        rule_result
    )

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    result = {

        "email": {
            "sender":
                email_data["sender"],

            "receiver":
                email_data["receiver"],

            "subject":
                email_data["subject"],

            "date":
                email_data["date"],
        },

        "header_model":
            header_result,

        "text_model":
            text_result,

        "rule_engine":
            rule_result,

        "m1_result":
            combined_result,
    }

    print("\n")
    print("=" * 70)
    print("M1 RESULT")
    print("=" * 70)

    print(
        f"Header class-1 probability : "
        f"{header_result['class_1_probability'] * 100:.2f}%"
    )

    print(
        f"Text class-1 probability   : "
        f"{text_result['class_1_probability'] * 100:.2f}%"
    )

    print(
        f"Rule score                 : "
        f"{rule_result['rule_score']:.2f}%"
    )

    print(
        f"Final prototype score      : "
        f"{combined_result['final_percentage']:.2f}%"
    )

    print(
        f"Verdict                    : "
        f"{combined_result['verdict']}"
    )

    return result


# ============================================================
# COMMAND LINE TEST
# ============================================================

if __name__ == "__main__":

    import sys
    import json

    if len(sys.argv) != 2:

        print(
            "\nUsage:"
        )

        print(
            "python m1_detector.py your_email.eml"
        )

        raise SystemExit(1)

    email_file = sys.argv[1]

    result = analyze_eml(
        email_file
    )

    print("\nComplete M1 JSON:")

    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False
        )
    )