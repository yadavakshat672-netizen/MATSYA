
from pathlib import Path
import json
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import cross_val_score

# Small demonstration dataset only.
# Replace these examples with a properly labeled email dataset
# before relying on model predictions.
TRAINING_DATA = [
    ("Urgent! Verify your account password immediately", "phishing"),
    ("Your bank account is suspended, click to restore access", "phishing"),
    ("You won a prize, claim it now using this link", "phishing"),
    ("Confirm your login credentials to avoid account closure", "phishing"),
    ("Invoice payment overdue, open the attached payment link", "phishing"),
    ("Security alert: verify your identity immediately", "phishing"),
    ("Your package delivery failed, pay a fee to reschedule", "phishing"),
    ("Reset your password using the official company portal", "legitimate"),
    ("Team meeting agenda for tomorrow afternoon", "legitimate"),
    ("Please find the monthly project report attached", "legitimate"),
    ("Your requested invoice is attached for review", "legitimate"),
    ("The office will be closed for the public holiday", "legitimate"),
    ("Thanks for attending the project status meeting", "legitimate"),
    ("Your appointment is confirmed for next Monday", "legitimate"),
    ("Please review the draft and share your feedback", "legitimate"),
    ("Quarterly sales report is ready for the team", "legitimate"),
]

def main():
    texts = [text for text, label in TRAINING_DATA]
    labels = [label for text, label in TRAINING_DATA]

    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            max_features=3000,
        )),
        ("classifier", LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42,
        )),
    ])

    model.fit(texts, labels)

    output_path = Path(__file__).parent / "email_model.joblib"
    joblib.dump(model, output_path)

    metadata = {
        "model_type": "TF-IDF + Logistic Regression",
        "training_examples": len(TRAINING_DATA),
        "classes": sorted(set(labels)),
        "warning": (
            "Toy demonstration dataset. Predictions are not reliable "
            "for real-world phishing detection."
        ),
    }

    metadata_path = Path(__file__).parent / "model_metadata.json"
    metadata_path.write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    print("Demo model trained and saved.")
    print(f"Model: {output_path}")
    print(f"Metadata: {metadata_path}")
    print("WARNING: This tiny demo dataset is not production-ready.")

if __name__ == "__main__":
    main()
