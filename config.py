import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'default-dev-key-change-in-production'
    
    # SQLAlchemy configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///budgetwise.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Google OAuth configuration
    GOOGLE_CLIENT_ID = '134432288601-qj4kg2hbmnvq7nu8ksrhs8lfkomnld2d.apps.googleusercontent.com'
    GOOGLE_CLIENT_SECRET = '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'
    GOOGLE_REDIRECT_URI = os.environ.get('GOOGLE_REDIRECT_URI', 'http://192.168.1.96:5000/oauth2callback')
    
    # Email senders to parse for transaction data
    EMAIL_SENDERS = {
        'gtbank': 'alerts@gtbank.com',
        'gtbank2': 'customerservice@gtbank.com', 
        'opay': 'donotreply@opay.com',
        'opay2': 'notifications@opay.com',
        'moniepoint': 'notifications@moniepoint.com',
        'moniepoint2': 'noreply@moniepoint.com',
        'palmpay': 'no-reply@palmpay.com',
        'accessbank': 'noreply@accessbank.com',
        'accessbank2': 'customerservice@accessbank.com',
        'firstbank': 'firstcontact@firstbanknigeria.com',
        'zenith': 'noreply@zenithbank.com',
        'fidelity': 'info@fidelitybank.ng',
        'uba': 'cfc@ubagroup.com',
        # Add more Nigerian banks/fintechs as needed
    }
    
    # Transaction keywords
    CREDIT_KEYWORDS = ['Credit', 'received', 'deposit', 'inflow']
    DEBIT_KEYWORDS = ['Debit', 'purchase', 'withdrawal', 'transfer', 'payment']
    
    # Transaction categories (Nigeria-specific)
    TRANSACTION_CATEGORIES = [
        'Airtime',
        'Data',
        'Transport',
        'Food',
        'Groceries',
        'Utility',
        'Rent',
        'Salary',
        'Hustle',
        'Transfer',
        'Received',
        'Shopping',
        'Entertainment',
        'Gift',
        'Other'
    ]

    # OAuth scopes needed for Gmail API
    GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.readonly'] 