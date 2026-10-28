
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from email import policy
from email.parser import BytesParser
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlparse
import ipaddress
import re
import joblib

app = FastAPI(
    title="MATSYA Cyber Intelligence API",
    description="Email forensics and experimental ML analysis",
    version="1.2.0",
)

# Allow the local React development server to call this API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_FILE_SIZE = 10 * 1024 * 1024

# Load the trained demonstration model.
MODEL_PATH = Path(__file__).parent / "email_model.joblib"

try:
    email_model = joblib.load(MODEL_PATH)
    ML_MODEL_STATUS = "loaded"
except (FileNotFoundError, OSError, ValueError, EOFError):
    email_model = None
    ML_MODEL_STATUS = "unavailable"


@app.get("/")
def home():
    return {
        "service": "MATSYA Cyber Intelligence API",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "ml_model_status": ML_MODEL_STATUS,
    }


@app.post("/api/analyze")
async def analyze_email(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Please upload a valid .eml file.",
        )

    raw = await file.read(MAX_FILE_SIZE + 1)

    if not raw:
        raise HTTPException(status_code=400, detail="The file is empty.")

    if len(raw) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="File exceeds the 10 MB limit.",
        )

    evidence_hash = sha256(raw).hexdigest()

    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail="Unable to parse this email file.",
        ) from exc

    subject = str(message.get("subject", ""))
    sender = str(message.get("from", ""))
    recipient = str(message.get("to", ""))
    date = str(message.get("date", ""))
    reply_to = str(message.get("reply-to", ""))

    headers = {
        str(key).lower(): str(value)
        for key, value in message.items()
    }

    # Extract readable email body content.
    body_parts = []

    for part in message.walk():
        if part.get_content_type() in ("text/plain", "text/html"):
            try:
                content = part.get_content()
                if isinstance(content, str):
                    body_parts.append(content)
            except Exception:
                continue

    body = "\n".join(body_parts)
    combined = raw.decode("utf-8", errors="replace")

    # Extract URLs and their hostnames.
    urls = sorted(
        set(
            re.findall(
                r"""https?://[^\s<>"')\]]+""",
                combined,
                flags=re.IGNORECASE,
            )
        )
    )[:200]

    domains = sorted({
        parsed.hostname
        for url in urls
        if (parsed := urlparse(url)).hostname
    })

    # Extract valid IPv4 addresses.
    candidates = set(
        re.findall(
            r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])",
            combined,
        )
    )

    ips = []

    for candidate in candidates:
        try:
            parsed_ip = ipaddress.ip_address(candidate)
            if parsed_ip.version == 4:
                ips.append(candidate)
        except ValueError:
            continue

    ips = sorted(set(ips))

    # Rule-based risk assessment.
    findings = []
    score = 10

    if not sender:
        findings.append("Sender information is missing.")
        score += 20

    if not subject:
        findings.append("Subject information is missing.")
        score += 10

    if urls:
        findings.append(
            f"{len(urls)} URL(s) extracted. Review destinations safely."
        )
        score += min(30, len(urls) * 10)

    if ips:
        findings.append(
            f"{len(ips)} IPv4 address(es) found; "
            "ownership and location are not verified."
        )
        score += min(15, len(ips) * 5)

    suspicious_words = [
        "verify your account",
        "urgent action",
        "password expired",
        "account suspended",
        "confirm your password",
        "immediate action",
    ]

    lowered = f"{subject} {body}".lower()
    matched = [word for word in suspicious_words if word in lowered]

    if matched:
        findings.append(
            "Potentially suspicious wording detected: "
            + ", ".join(matched)
        )
        score += min(30, 10 * len(matched))

    auth_results = headers.get("authentication-results", "").lower()

    if any(
        token in auth_results
        for token in ("spf=fail", "dkim=fail", "dmarc=fail")
    ):
        findings.append(
            "Authentication-Results indicates an SPF, DKIM, "
            "or DMARC failure."
        )
        score += 20

    score = min(score, 100)
    risk_level = (
        "High" if score >= 70
        else "Medium" if score >= 40
        else "Low"
    )

    if not findings:
        findings.append(
            "No indicators from the current basic rules were found."
        )

    # Experimental ML prediction.
    ml_prediction = "unavailable"
    ml_probability = None

    if email_model is not None:
        ml_text = f"{subject}\n{body}"

        try:
            ml_prediction = str(email_model.predict([ml_text])[0])

            if hasattr(email_model, "predict_proba"):
                probabilities = email_model.predict_proba([ml_text])[0]
                classes = list(email_model.classes_)

                if "phishing" in classes:
                    index = classes.index("phishing")
                    ml_probability = round(
                        float(probabilities[index]), 4
                    )

        except Exception:
            # Preserve the forensic analysis if ML prediction fails.
            ml_prediction = "prediction_error"
            ml_probability = None

    limitations = [
        "Risk score is based on basic heuristic rules.",
        "The ML model uses a tiny demonstration dataset and is not "
        "reliable for real-world phishing decisions.",
        "No live IP/domain reputation or geolocation lookup is performed.",
        "Extracted URLs are not opened or executed.",
        "A low score does not prove an email is safe.",
        "Graph connections represent extracted associations and need "
        "analyst validation.",
    ]

    if ML_MODEL_STATUS != "loaded":
        limitations.append(
            "The ML model file could not be loaded; ML prediction is unavailable."
        )

    return {
        "filename": file.filename,
        "sha256": evidence_hash,
        "file_size": len(raw),
        "report": {
            "subject": subject,
            "sender": sender,
            "recipient": recipient,
            "date": date,
            "reply_to": reply_to,
            "headers": headers,
            "urls": urls,
            "domains": domains,
            "ips": ips,
            "risk_score": score,
            "risk_level": risk_level,
            "ml_prediction": ml_prediction,
            "ml_probability": ml_probability,
            "ml_model_status": ML_MODEL_STATUS,
            "findings": findings,
            "limitations": limitations,
        },
    }
