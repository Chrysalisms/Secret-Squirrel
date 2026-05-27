// Integration test: Python app using DB_PASSWORD from environment
// Part of the 3-file correlation chain: .env → docker-compose.yml → app.py
// Used by: tests/integration/pipeline_e2e.rs correlation tests

import os
import psycopg2

DB_PASSWORD = os.getenv("DB_PASSWORD", "super_secret_password_123")
OPENAI_KEY = "sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRS"

def connect_db():
    conn = psycopg2.connect(
        host="prod.db.example.com",
        database="mydb",
        user="admin",
        password=DB_PASSWORD,
    )
    return conn

def call_openai(prompt: str) -> str:
    import openai
    openai.api_key = OPENAI_KEY
    return openai.Completion.create(model="gpt-4", prompt=prompt)
