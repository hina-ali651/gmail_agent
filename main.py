import os
import base64
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
from email.mime.text import MIMEText
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from dotenv import load_dotenv
from pydantic import BaseModel

load_dotenv()

app = FastAPI()

# Constants
GMAIL_SEND_URL = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")
DATABASE_URL = os.getenv("DATABASE_URL")

# DB Connection
def get_db_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

# Save tokens in DB
def save_tokens(user_email, access_token, refresh_token):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS google_tokens (
            id SERIAL PRIMARY KEY,
            user_email TEXT NOT NULL,
            access_token TEXT,
            refresh_token TEXT
        )
    """)
    cur.execute("""
        INSERT INTO google_tokens (user_email, access_token, refresh_token)
        VALUES (%s, %s, %s)
    """, (user_email, access_token, refresh_token))
    conn.commit()
    cur.close()
    conn.close()

# Get latest refresh token for a user
def get_refresh_token(user_email):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT refresh_token FROM google_tokens
        WHERE user_email=%s
        ORDER BY id DESC LIMIT 1
    """, (user_email,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row['refresh_token'] if row else None

# Refresh access token
def refresh_access_token(refresh_token):
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token"
    }
    r = requests.post(token_url, data=data)
    return r.json().get("access_token")

@app.get("/auth/google/start")
def google_oauth_start():
    auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        "&response_type=code"
        "&scope=openid%20email%20https://www.googleapis.com/auth/gmail.send"
        "&access_type=offline"
        "&prompt=consent"
    )
    return RedirectResponse(auth_url)


@app.get("/auth/google/callback")
def google_oauth_callback(code: str):
    # Step 1: Get access & refresh token
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code"
    }

    r = requests.post(token_url, data=data)
    tokens = r.json()

    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")

    # Step 2: Get user email from Google
    user_info = requests.get(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {access_token}"}
    ).json()

    user_email = user_info.get("email")

    # Step 3: Save tokens
    if refresh_token and user_email:
        save_tokens(user_email, access_token, refresh_token)

    return {
        "message": "Tokens saved successfully!",
        "user_email": user_email,
        "tokens": tokens
    }
