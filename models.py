from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from extensions import db

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(256), nullable=False)
    gmail_token = db.Column(db.Text, nullable=True)
    gmail_refresh_token = db.Column(db.Text, nullable=True)
    gmail_token_expiry = db.Column(db.DateTime, nullable=True)
    imap_server = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship: one user can have many transactions
    transactions = db.relationship('Transaction', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def has_gmail_access(self):
        return bool(self.gmail_token and self.gmail_refresh_token)
    
    def has_email_access(self):
        """Check if user has any email access (Gmail OAuth or IMAP)."""
        return self.has_gmail_access() or bool(self.email and self.imap_server)

class Transaction(db.Model):
    __tablename__ = 'transactions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    transaction_type = db.Column(db.String(10), nullable=False)  # 'income' or 'expense'
    transaction_date = db.Column(db.Date, nullable=False)
    email_id = db.Column(db.String(100), nullable=True)  # For detecting duplicates
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Transaction {self.amount} {self.transaction_type} on {self.transaction_date}>' 