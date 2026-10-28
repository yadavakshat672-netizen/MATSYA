

from contextlib import asynccontextmanager

from email import policy

from email.parser import BytesParser

from hashlib import sha256

from pathlib import Path

from urllib.parse import urlparse

import ipaddress

import json

import re



import joblib

from fastapi import FastAPI, UploadFile, File, HTTPException

from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy import inspect, text



from database import engine, SessionLocal

from models import InvestigationCase, create_tables

from intelligence import router as intelligence_router





# --------------------------------------------------

# MATSYA CONFIGURATION

# --------------------------------------------------



MAX_FILE_SIZE = 10 * 1024 * 1024

BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = BASE_DIR / "email_model.joblib"





def initialize_database():

    """Create tables and safely update the existing cases table."""

    create_tables()



    inspector = inspect(engine)

    columns = {

        column["name"]

        for column in inspector.get_columns("investigation_cases")

    }



    # The earlier version of the database may not have this column.

    if "evidence_hash" not in columns:

        with engine.begin() as connection:

            connection.execute(

                text(

                    "ALTER TABLE investigation_cases "

                    "ADD COLUMN evidence_hash VARCHAR(64)"

                )

            )





@asynccontextmanager

async def lifespan(app: FastAPI):

    initialize_database()

    yield





app = FastAPI(

    title="MATSYA Cyber Intelligence API",

    description="Email forensics, experimental ML analysis, and SQLite case history",

    version="1.3.0",

    lifespan=lifespan,

)





# Local development CORS settings.

app.add_middleware(

    CORSMiddleware,

    allow_origins=[

        "http://localhost:5173",

        "http://127.0.0.1:5173",

        "http://localhost:5174",

        "http://127.0.0.1:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5175",
        "http://localhost:5176",
        "http://127.0.0.1:5176",

        "http://localhost:5190",

        "http://127.0.0.1:5190",

    ],

    allow_credentials=False,

    allow_methods=["*"],

    allow_headers=["*"],

)



# Preserve existing threat-intelligence endpoints.

app.include_router(intelligence_router)





# --------------------------------------------------

# OPTIONAL ML MODEL

# --------------------------------------------------



try:

    email_model = joblib.load(MODEL_PATH)

    ML_MODEL_STATUS = "loaded"

except Exception as exc:

    email_model = None

    ML_MODEL_STATUS = "unavailable"

    print(f"ML model unavailable: {exc}")





# --------------------------------------------------

# HOME AND HEALTH

# --------------------------------------------------



@app.get("/")

def home():

    return {

        "service": "MATSYA Cyber Intelligence API",

        "status": "running",

        "database": "SQLite",

        "docs": "/docs",

    }





@app.get("/api/health")

def health():

    database_status = "connected"



    try:

        with engine.connect() as connection:

            connection.execute(text("SELECT 1"))

    except Exception as exc:

        database_status = "unavailable"

        print(f"Database health check failed: {exc}")



    return {

        "status": "healthy" if database_status == "connected" else "degraded",

        "database_status": database_status,

        "ml_model_status": ML_MODEL_STATUS,

    }





# --------------------------------------------------

# EMAIL ANALYSIS

# --------------------------------------------------



@app.post("/api/analyze")

async def analyze_email(file: UploadFile = File(...)):

    if not file.filename or not file.filename.lower().endswith(".eml"):

        raise HTTPException(

            status_code=400,

            detail="Please upload a valid .eml file.",

        )



    raw = await file.read(MAX_FILE_SIZE + 1)



    if not raw:

        raise HTTPException(

            status_code=400,

            detail="The file is empty.",

        )



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



    # Extract email metadata.

    subject = str(message.get("subject", ""))

    sender = str(message.get("from", ""))

    recipient = str(message.get("to", ""))

    date = str(message.get("date", ""))

    reply_to = str(message.get("reply-to", ""))



    headers = {

        str(key).lower(): str(value)

        for key, value in message.items()

    }



    # Extract readable body text.

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



    # Extract URLs without opening them.

    urls = sorted(

        set(

            re.findall(

                r"""https?://[^\s<>"')\]]+""",

                combined,

                flags=re.IGNORECASE,

            )

        )

    )[:200]



    # Extract hostnames from URLs.

    domains = sorted(

        {

            parsed.hostname

            for url in urls

            if (parsed := urlparse(url)).hostname

        }

    )



    # Extract and validate IPv4 addresses.

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



    # --------------------------------------------------

    # TRANSPARENT HEURISTIC RISK SCORING

    # --------------------------------------------------



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

    matched = [

        word for word in suspicious_words

        if word in lowered

    ]



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



    if score >= 70:

        risk_level = "High"

    elif score >= 40:

        risk_level = "Medium"

    else:

        risk_level = "Low"



    if not findings:

        findings.append(

            "No indicators from the current basic rules were found."

        )



    # --------------------------------------------------

    # EXPERIMENTAL ML PREDICTION

    # --------------------------------------------------



    ml_prediction = "unavailable"

    ml_probability = None



    if email_model is not None:

        ml_text = f"{subject}\n{body}"



        try:

            ml_prediction = str(email_model.predict([ml_text])[0])



            if hasattr(email_model, "predict_proba"):

                probabilities = email_model.predict_proba([ml_text])[0]

                classes = list(getattr(email_model, "classes_", []))



                phishing_index = next(

                    (

                        index

                        for index, label in enumerate(classes)

                        if str(label).lower() == "phishing"

                    ),

                    None,

                )



                if (

                    phishing_index is not None

                    and phishing_index < len(probabilities)

                ):

                    ml_probability = round(

                        float(probabilities[phishing_index]), 4

                    )



        except Exception as exc:

            print(f"ML prediction failed: {exc}")

            ml_prediction = "prediction_error"

            ml_probability = None



    # --------------------------------------------------

    # LIMITATIONS

    # --------------------------------------------------



    limitations = [

        "Risk score is based on basic heuristic rules.",

        "The ML model uses a demonstration dataset and is not "

        "reliable for real-world phishing decisions.",

        "No live IP/domain reputation or geolocation lookup is performed.",

        "Extracted URLs are not opened or executed.",

        "A low score does not prove an email is safe.",

        "Extracted IP addresses and domains require analyst validation.",

    ]



    if ML_MODEL_STATUS != "loaded":

        limitations.append(

            "The ML model file could not be loaded; "

            "ML prediction is unavailable."

        )



    # --------------------------------------------------

    # SAVE ANALYSIS TO SQLITE

    # --------------------------------------------------



    saved_case_id = None

    db = SessionLocal()



    try:

        saved_case = InvestigationCase(

            case_title=subject.strip() or file.filename,

            sender_email=sender or None,

            subject=subject or None,

            risk_score=score,

            risk_level=risk_level,

            findings=json.dumps(findings, ensure_ascii=False),

            evidence_hash=evidence_hash,

        )



        db.add(saved_case)

        db.commit()

        db.refresh(saved_case)

        saved_case_id = saved_case.id



    except Exception as exc:

        db.rollback()

        print(f"Database save failed: {exc}")



    finally:

        db.close()



    # Preserve the existing analysis response fields.

    return {

        "case_id": saved_case_id,

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





# --------------------------------------------------

# SAVED CASES API

# --------------------------------------------------



@app.get("/api/cases")

def get_cases():

    db = SessionLocal()



    try:

        cases = (

            db.query(InvestigationCase)

            .order_by(InvestigationCase.id.desc())

            .all()

        )



        return {

            "total": len(cases),

            "cases": [

                {

                    "id": case.id,

                    "case_title": case.case_title,

                    "sender_email": case.sender_email,

                    "subject": case.subject,

                    "risk_score": case.risk_score,

                    "risk_level": case.risk_level,

                    "findings": (

                        json.loads(case.findings)

                        if case.findings

                        else []

                    ),

                    "evidence_hash": case.evidence_hash,

                    "created_at": (

                        case.created_at.isoformat()

                        if case.created_at

                        else None

                    ),

                }

                for case in cases

            ],

        }



    finally:

        db.close()





@app.get("/api/cases/{case_id}")

def get_case(case_id: int):

    db = SessionLocal()



    try:

        case = (

            db.query(InvestigationCase)

            .filter(InvestigationCase.id == case_id)

            .first()

        )



        if case is None:

            raise HTTPException(

                status_code=404,

                detail="Investigation case not found.",

            )



        try:

            findings = json.loads(case.findings) if case.findings else []

        except json.JSONDecodeError:

            findings = []



        return {

            "id": case.id,

            "case_title": case.case_title,

            "sender_email": case.sender_email,

            "subject": case.subject,

            "risk_score": case.risk_score,

            "risk_level": case.risk_level,

            "findings": findings,

            "evidence_hash": case.evidence_hash,

            "created_at": (

                case.created_at.isoformat()

                if case.created_at

                else None

            ),

        }



    finally:

        db.close()
