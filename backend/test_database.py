
from database import engine

with engine.connect():
    print("MATSYA SQLite database connected successfully!")

print("Database file will be created when SQLite first connects.")
