# MATSYA Cyber Forensics — React + FastAPI

## Run frontend
Open a terminal in the project root:
```powershell
npm.cmd install
npm.cmd run dev
```

## Run backend
Open a second terminal in the project root:
```powershell
cd backend
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
```

Open `http://127.0.0.1:8000/docs` to inspect the API and `http://127.0.0.1:8000/api/health` to check the service.

## Email analysis flow
1. Sign in using any non-empty demo credentials.
2. Create a case in Case Management.
3. Open Upload Evidence and choose an `.eml` file.
4. Click Analyze evidence. The browser sends the file to the local FastAPI service.
5. Review backend findings in Analysis Results and open Attack Graph to inspect extracted entities.

## Important limitations
- Demo login is not production authentication.
- Cases are held in React memory and are not saved to a persistent database.
- Scoring uses transparent basic rules, not a trained AI/ML model.
- No external threat-intelligence APIs or live geolocation are configured.
- Graph edges are associations based on extracted content, not proof of malicious relationships.
