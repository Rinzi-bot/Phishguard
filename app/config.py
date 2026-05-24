import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")
    SQLALCHEMY_DATABASE_URI = "sqlite:///phishguard.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Your trusted internal/company domains
    INTERNAL_DOMAINS = ["cihe.edu.au", "yourcompany.com"]

    ALLOWED_EXTENSIONS = {"eml", "txt"}