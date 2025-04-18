import os
import re
import json
import base64
import datetime
from functools import wraps
from email.utils import parsedate_to_datetime

# Allow OAuth over HTTP for development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError

import google.oauth2.credentials
import google_auth_oauthlib.flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

from config import Config
from extensions import db, login_manager
from models import User, Transaction
import imaplib
from imap_sync import connect_to_imap, fetch_and_process_emails

# Get absolute path to templates and static folders
template_dir = os.path.abspath('app/templates')
static_dir = os.path.abspath('app/static')

# Initialize Flask app
app = Flask(__name__, 
            template_folder=template_dir,
            static_folder=static_dir)
app.config.from_object(Config)

# Ensure session cookie is secure and with SameSite policy
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=5)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(os.getcwd(), 'flask_session')

# Initialize session
Session(app)

# Initialize extensions
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'  # type: ignore

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Ensure Gmail API access is limited to user's own context
def gmail_access_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.has_gmail_access():
            flash('Please connect your Gmail account first', 'warning')
            return redirect(url_for('connect_email'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        phone = request.form.get('phone')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Basic validation
        if not phone or not password:
            flash('Phone number and password are required', 'danger')
            return render_template('signup.html')
        
        # Nigerian phone number validation (simple)
        if not phone.isdigit() or len(phone) != 11 or not phone.startswith('0'):
            flash('Please enter a valid Nigerian phone number (e.g., 08012345678)', 'danger')
            return render_template('signup.html')
            
        # Create new user
        try:
            user = User(phone=phone, email=email)  # type: ignore
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash('Account created successfully!', 'success')
            return redirect(url_for('connect_email'))
        except IntegrityError:
            db.session.rollback()
            flash('Phone number or email already registered', 'danger')
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        phone = request.form.get('phone')
        password = request.form.get('password')
        
        user = User.query.filter_by(phone=phone).first()
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid phone number or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get transaction data
    print(f"Current user ID: {current_user.id}")
    transactions = Transaction.query.filter_by(user_id=current_user.id)\
                                 .order_by(Transaction.transaction_date.desc())\
                                 .all()
    
    print(f"Number of transactions found: {len(transactions)}")
    if transactions:
        print(f"First transaction: {transactions[0].id}, {transactions[0].description}, {transactions[0].amount}")
    
    # Calculate summaries
    total_income = sum(t.amount for t in transactions if t.transaction_type == 'income')
    total_expense = sum(t.amount for t in transactions if t.transaction_type == 'expense')
    savings = total_income - total_expense
    
    print(f"Total income: {total_income}, Total expense: {total_expense}")
    
    # Prepare data for charts (basic implementation)
    categories = {}
    for t in transactions:
        if t.transaction_type == 'expense':
            if t.category in categories:
                categories[t.category] += t.amount
            else:
                categories[t.category] = t.amount
    
    return render_template(
        'dashboard.html',
        transactions=transactions,
        total_income=total_income,
        total_expense=total_expense,
        savings=savings,
        categories=app.config['TRANSACTION_CATEGORIES'],
        spending_by_category=categories,
        user_email=current_user.email
    )

@app.route('/connect_email')
@login_required
def connect_email():
    return render_template('connect_email.html')

@app.route('/authorize')
@login_required
def authorize():
    # Create flow instance to manage OAuth 2.0 Authorization Grant Flow
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        'client_secrets.json',
        scopes=['https://www.googleapis.com/auth/gmail.readonly']
    )
    
    # Set the redirect URI
    flow.redirect_uri = app.config['GOOGLE_REDIRECT_URI']
    
    # Generate URL for request to Google's OAuth 2.0 server
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'  # Force to get refresh_token
    )
    
    # Store the state in the session for later validation
    session['state'] = state
    session.modified = True
    
    return redirect(authorization_url)

@app.route('/oauth2callback')
@login_required
def oauth2callback():
    # Specify the state when creating the flow in the callback
    state = session.get('state', None)
    
    if state is None:
        flash('Session state missing. Please try connecting again.', 'danger')
        return redirect(url_for('connect_email'))
    
    # Clear the state to prevent replay attacks
    session.pop('state', None)
    session.modified = True
    
    try:
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
            'client_secrets.json',
            scopes=['https://www.googleapis.com/auth/gmail.readonly'],
            state=state
        )
        flow.redirect_uri = app.config['GOOGLE_REDIRECT_URI']
        
        # Use the authorization server's response to fetch the OAuth 2.0 tokens
        authorization_response = request.url
        flow.fetch_token(authorization_response=authorization_response)
        
        # Store credentials in the database
        credentials = flow.credentials
        current_user.gmail_token = credentials.token
        current_user.gmail_refresh_token = credentials.refresh_token
        expiry = credentials.expiry.replace(tzinfo=None) if credentials.expiry else None
        current_user.gmail_token_expiry = expiry
        
        db.session.commit()
        flash('Gmail connected successfully!', 'success')
        
        return redirect(url_for('sync_transactions'))
    except Exception as e:
        flash(f'Error connecting Gmail: {str(e)}', 'danger')
        return redirect(url_for('connect_email'))

@app.route('/sync_transactions')
@login_required
@gmail_access_required
def sync_transactions():
    # Build the Gmail API client
    credentials = google.oauth2.credentials.Credentials(
        token=current_user.gmail_token,
        refresh_token=current_user.gmail_refresh_token,
        token_uri='https://oauth2.googleapis.com/token',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET']
    )
    
    # Check if token needs refresh
    if current_user.gmail_token_expiry and current_user.gmail_token_expiry < datetime.datetime.utcnow():
        credentials.refresh(Request())
        current_user.gmail_token = credentials.token
        current_user.gmail_token_expiry = credentials.expiry.replace(tzinfo=None) if credentials.expiry else None
        db.session.commit()
    
    service = build('gmail', 'v1', credentials=credentials)
    
    # Get email senders from config
    senders = app.config['EMAIL_SENDERS'].values()
    
    # Construct query to find transaction emails
    query = ' OR '.join([f'from:{sender}' for sender in senders])
    
    # Use a longer timeframe (90 days instead of 30) for first sync
    days_to_search = 90 if not Transaction.query.filter_by(user_id=current_user.id).first() else 30
    query += f' newer_than:{days_to_search}d'  # Adjust search period
    
    print(f"Searching emails with query: {query}")  # Debug log
    
    # Get messages matching query
    results = service.users().messages().list(userId='me', q=query).execute()
    messages = results.get('messages', [])
    
    print(f"Found {len(messages)} matching emails")  # Debug log
    
    # If no messages found, provide more detailed feedback
    if not messages:
        flash('No transaction emails found from any supported banks. This could mean:')
        flash('1. You don\'t have any bank transaction emails in your Gmail', 'info')
        flash('2. Your bank is not yet supported by our system', 'info')
        flash('3. Your emails are older than 90 days', 'info')
        return redirect(url_for('dashboard'))
    
    transaction_count = 0
    
    # Process each email
    for message in messages:
        msg = service.users().messages().get(userId='me', id=message['id'], format='full').execute()
        
        # Check if we've already processed this email
        existing = Transaction.query.filter_by(email_id=message['id']).first()
        if existing:
            continue
        
        # Extract email body
        payload = msg['payload']
        body = ''
        
        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                    break
        elif 'body' in payload and 'data' in payload['body']:
            body = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8')
        
        # Extract headers
        headers = payload['headers']
        sender = next((h['value'] for h in headers if h['name'] == 'From'), None)
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), None)
        date_str = next((h['value'] for h in headers if h['name'] == 'Date'), None)
        
        print(f"Processing email from: {sender}, subject: {subject}")  # Debug log
        
        # Parse transaction data using regex patterns
        transaction = parse_transaction_email(body, subject, sender)
        
        if transaction:
            print(f"Extracted transaction: {transaction}")  # Debug log
            
            # Get transaction date from email headers if not extracted from body
            if not transaction.get('date'):
                if date_str:
                    try:
                        email_date = parsedate_to_datetime(date_str).date()
                        transaction['date'] = email_date
                    except:
                        transaction['date'] = datetime.date.today()
                else:
                    transaction['date'] = datetime.date.today()
            
            # Determine transaction type based on keywords
            transaction_type = 'expense'  # Default
            description = transaction.get('description', '').lower()
            
            # Check for income keywords
            for keyword in app.config['CREDIT_KEYWORDS']:
                if keyword in description:
                    transaction_type = 'income'
                    break
            
            # Check for expense keywords that override
            for keyword in app.config['DEBIT_KEYWORDS']:
                if keyword in description:
                    transaction_type = 'expense'
                    break
            
            # Determine category based on  keywords (basic implementation)
            category = categorize_transaction(transaction.get('description', ''))
            
            # Create new transaction record
            new_transaction = Transaction(  # type: ignore
                user_id=current_user.id, #type: ignore
                amount=transaction.get('amount', 0), #type: ignore
                description=transaction.get('description', 'Unknown transaction'), #type: ignore
                category=category, #type: ignore
                transaction_type=transaction_type, #type: ignore
                transaction_date=transaction.get('date'), #type: ignore
                email_id=message['id'] #type: ignore
            )
            
            db.session.add(new_transaction)
            transaction_count += 1
        else:
            print(f"Could not extract transaction from email with subject: {subject}")  # Better debug log
    
    # Commit all transactions to database
    if transaction_count > 0:
        db.session.commit()
        flash(f'Successfully imported {transaction_count} transactions', 'success')
    else:
        flash('No new transactions found. This could mean:', 'warning')
        flash('1. Our system couldn\'t parse your bank email formats', 'info')
        flash('2. You have transaction emails but they don\'t contain transaction data in expected format', 'info')
        flash('3. All your transaction emails have already been imported', 'info')
    
    return redirect(url_for('dashboard'))

@app.route('/disconnect_email')
@login_required
def disconnect_email():
    # Clear email connection credentials
    if current_user.has_gmail_access():
        # Clear Gmail OAuth tokens
        current_user.gmail_token = None
        current_user.gmail_refresh_token = None
        current_user.gmail_token_expiry = None
        flash('Gmail account disconnected successfully', 'success')
    else:
        # Clear IMAP connection info
        current_user.imap_server = None
        flash('Email account disconnected successfully', 'success')
    
    db.session.commit()
    return redirect(url_for('connect_email'))

@app.route('/test_gmail_connection')
@login_required
@gmail_access_required
def test_gmail_connection():
    """Test route to verify Gmail API connection and show email stats."""
    try:
        # Build the Gmail API client
        credentials = google.oauth2.credentials.Credentials(
            token=current_user.gmail_token,
            refresh_token=current_user.gmail_refresh_token,
            token_uri='https://oauth2.googleapis.com/token',
            client_id=app.config['GOOGLE_CLIENT_ID'],
            client_secret=app.config['GOOGLE_CLIENT_SECRET']
        )
        
        # Check if token needs refresh
        if current_user.gmail_token_expiry and current_user.gmail_token_expiry < datetime.datetime.utcnow():
            credentials.refresh(Request())
            current_user.gmail_token = credentials.token
            current_user.gmail_token_expiry = credentials.expiry.replace(tzinfo=None) if credentials.expiry else None
            db.session.commit()
        
        service = build('gmail', 'v1', credentials=credentials)
        
        # Basic profile info
        profile = service.users().getProfile(userId='me').execute()
        
        # Get email senders from config
        senders = app.config['EMAIL_SENDERS'].values()
        
        # Get stats for each sender
        sender_stats = {}
        for sender in senders:
            # Query for emails from this sender in the last 90 days
            query = f'from:{sender} newer_than:90d'
            results = service.users().messages().list(userId='me', q=query).execute()
            messages = results.get('messages', [])
            sender_stats[sender] = len(messages)
        
        # Find total email count
        total_query = ' OR '.join([f'from:{sender}' for sender in senders])
        total_query += ' newer_than:90d'
        total_results = service.users().messages().list(userId='me', q=total_query).execute()
        total_messages = total_results.get('messages', [])
        
        return render_template('test_gmail.html', 
                               email=profile.get('emailAddress'),
                               total_count=len(total_messages),
                               sender_stats=sender_stats)
    except Exception as e:
        flash(f'Error testing Gmail connection: {str(e)}', 'danger')
        return redirect(url_for('connect_email'))

@app.route('/connect_imap', methods=['GET', 'POST'])
@login_required
def connect_imap():
    """Route to connect email via IMAP."""
    if request.method == 'POST':
        email_address = request.form.get('email')
        password = request.form.get('password')
        imap_server = request.form.get('imap_server') or 'imap.gmail.com'
        
        # Store IMAP credentials (in encrypted form in production)
        # For simplicity, we're storing plaintext here, but in production use encryption
        current_user.email = email_address
        # Don't store password in user table in production
        # Instead, use a secure method like a separate encrypted storage
        current_user.imap_server = imap_server
        db.session.commit()
        
        # Test connection
        try:
            mail = connect_to_imap(email_address, password, imap_server)
            if mail:
                mail.logout()
                flash('Email connection successful!', 'success')
                return redirect(url_for('sync_imap_transactions'))
            else:
                flash('Could not connect to email server. Please check your credentials.', 'danger')
        except Exception as e:
            flash(f'Error connecting to email: {str(e)}', 'danger')
    
    return render_template('connect_imap.html')

@app.route('/sync_imap_transactions')
@login_required
def sync_imap_transactions():
    """Sync transactions using IMAP."""
    if not current_user.email or not request.args.get('password'):
        flash('Please provide your email password to sync transactions', 'warning')
        return redirect(url_for('connect_imap'))
    
    password = request.args.get('password')
    imap_server = current_user.imap_server or 'imap.gmail.com'
    
    try:
        # Connect to IMAP
        mail = connect_to_imap(current_user.email, password, imap_server)
        if not mail:
            flash('Failed to connect to email server. Please check your credentials.', 'danger')
            return redirect(url_for('connect_imap'))
        
        # Fetch and process emails
        transaction_count = fetch_and_process_emails(mail, current_user.id)
        
        # Log out
        mail.logout()
        
        if transaction_count > 0:
            flash(f'Successfully imported {transaction_count} transactions', 'success')
        else:
            flash('No new transactions found. This could mean:', 'info')
            flash('1. No transaction emails from supported banks were found in your inbox', 'info')
            flash('2. All transaction emails have already been processed', 'info')
            flash('3. The transaction emails could not be parsed correctly', 'info')
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Error syncing transactions: {str(e)}")
        print(error_details)
        flash(f'Error syncing transactions: {str(e)}', 'danger')
    
    return redirect(url_for('dashboard'))

# Helper functions
def parse_transaction_email(body, subject, sender):
    """Extract transaction details from email body using regex patterns."""
    transaction = {}
    
    print(f"Attempting to parse email - Subject: {subject}")
    print(f"Email sender: {sender}")
    
    # Clean the input - some emails have weird formatting
    body = body.replace('\r', ' ').replace('\n', ' ')
    
    # Print a sample of the body (first 100 chars)
    print(f"Email body sample: {body[:100]}...")
    
    # Extract any amount using flexible patterns - cover all Nigerian banks
    # Look for common patterns like NGN, ₦, N followed by numbers
    # Also look for words like "amount" or "sum" near numbers
    amount_patterns = [
        r'NGN\s*([\d,]+\.\d{2})',
        r'NGN\s*([\d,]+)',
        r'₦\s*([\d,]+\.\d{2})',
        r'₦\s*([\d,]+)',
        r'N\s*([\d,]+\.\d{2})',
        r'N\s*([\d,]+)',
        r'amount\s*:?\s*(?:NGN|₦|N)?\s*([\d,]+\.\d{2})',
        r'amount\s*:?\s*(?:NGN|₦|N)?\s*([\d,]+)',
        r'sum\s*:?\s*(?:NGN|₦|N)?\s*([\d,]+\.\d{2})',
        r'sum\s*:?\s*(?:NGN|₦|N)?\s*([\d,]+)',
        r'value\s*:?\s*(?:NGN|₦|N)?\s*([\d,]+\.\d{2})',
        r'value\s*:?\s*(?:NGN|₦|N)?\s*([\d,]+)',
    ]
    
    # Try all amount patterns until one matches
    for pattern in amount_patterns:
        amount_match = re.search(pattern, body, re.IGNORECASE)
        if amount_match:
            amount_str = amount_match.group(1).replace(',', '')
            # Handle amounts without decimal points
            if '.' not in amount_str:
                amount_str += '.00'
            transaction['amount'] = float(amount_str)
            print(f"Found amount: {transaction['amount']} using pattern {pattern}")
            break
    
    # If amount not found, try to add a fallback for common formats
    if 'amount' not in transaction:
        # Try to find any number with currency or money context
        money_fallback = re.search(r'(?:NGN|₦|N|amount|sum|value|debit|credit).*?(\d[\d,.]+)', body, re.IGNORECASE)
        if money_fallback:
            amount_str = money_fallback.group(1).replace(',', '')
            if '.' not in amount_str:
                amount_str += '.00'
            transaction['amount'] = float(amount_str)
            print(f"Found amount using fallback: {transaction['amount']}")
    
    # Extract description using various bank patterns
    desc_patterns = [
        r'description\s*:?\s*(.*?)(?:date|amount|time|balance|\.|$)',
        r'narration\s*:?\s*(.*?)(?:date|amount|time|balance|\.|$)',
        r'transaction\s*:?\s*(.*?)(?:date|amount|time|balance|\.|$)',
        r'details\s*:?\s*(.*?)(?:date|amount|time|balance|\.|$)',
        r'info\s*:?\s*(.*?)(?:date|amount|time|balance|\.|$)',
        r'payment\s*for\s*:?\s*(.*?)(?:date|amount|time|balance|\.|$)',
        r'credited\s*(?:with|from)\s*:?\s*(.*?)(?:date|amount|time|balance|\.|$)',
        r'debited\s*(?:with|for)\s*:?\s*(.*?)(?:date|amount|time|balance|\.|$)',
        r'transferred\s*to\s*:?\s*(.*?)(?:date|amount|time|balance|\.|$)',
        r'received\s*from\s*:?\s*(.*?)(?:date|amount|time|balance|\.|$)',
    ]
    
    # Try all description patterns until one matches
    for pattern in desc_patterns:
        desc_match = re.search(pattern, body, re.IGNORECASE)
        if desc_match:
            desc = desc_match.group(1).strip()
            # Clean up the description
            transaction['description'] = re.sub(r'\s+', ' ', desc)
            print(f"Found description: {transaction['description']}")
            break
    
    # If no description found, try to extract it from subject
    if 'description' not in transaction and subject:
        # Common subjects contain transaction type and may include amount
        debit_patterns = [r'debit alert', r'purchase', r'payment', r'transfer', r'withdrawal']
        credit_patterns = [r'credit alert', r'deposit', r'received']
        
        for pattern in debit_patterns:
            if re.search(pattern, subject, re.IGNORECASE):
                transaction['description'] = subject
                print(f"Using subject as description (debit): {subject}")
                break
                
        for pattern in credit_patterns:
            if re.search(pattern, subject, re.IGNORECASE):
                transaction['description'] = subject
                print(f"Using subject as description (credit): {subject}")
                break
    
    # Last resort: just use the subject
    if 'description' not in transaction and subject:
        transaction['description'] = subject
        print(f"Using subject as fallback description: {subject}")
    
    # Try to extract date
    date_patterns = [
        r'date\s*:?\s*(\d{1,2}[-/\.]\d{1,2}[-/\.]\d{2,4})',
        r'on\s*:?\s*(\d{1,2}[-/\.]\d{1,2}[-/\.]\d{2,4})',
        r'(\d{1,2}[-/\.]\d{1,2}[-/\.]\d{2,4})\s*at',
    ]
    
    for pattern in date_patterns:
        date_match = re.search(pattern, body, re.IGNORECASE)
        if date_match:
            date_str = date_match.group(1)
            # Try different date formats
            for fmt in ['%d/%m/%Y', '%d-%m-%Y', '%d.%m.%Y', '%d/%m/%y', '%d-%m-%y', '%d.%m.%y']:
                try:
                    transaction['date'] = datetime.datetime.strptime(date_str, fmt).date()
                    print(f"Found date: {transaction['date']}")
                    break
                except ValueError:
                    continue
            if 'date' in transaction:
                break
    
    # Log result of parsing
    if 'amount' in transaction:
        print(f"Successfully parsed transaction: {transaction}")
    else:
        print("Failed to parse transaction - no amount found")
    
    # Return transaction details if amount was found, otherwise None
    return transaction if 'amount' in transaction else None

def categorize_transaction(description):
    """Categorize transaction based on keywords in description."""
    description = description.lower()
    
    category_keywords = {
        'Airtime': ['airtime', 'recharge', 'top-up', 'top up', 'mtn', 'glo', 'airtel', '9mobile'],
        'Data': ['data', 'internet', 'bundle'],
        'Transport': ['uber', 'bolt', 'taxi', 'transport', 'bus', 'fare', 'ride', 'commute'],
        'Food': ['food', 'restaurant', 'eatery', 'eating', 'lunch', 'dinner', 'breakfast', 'cafe', 'cafeteria'],
        'Groceries': ['groceries', 'supermarket', 'market', 'store', 'shopping'],
        'Utility': ['dstv', 'gotv', 'electricity', 'water', 'bill', 'utility', 'nepa', 'phcn', 'ikedc', 'subscription'],
        'Rent': ['rent', 'house', 'accommodation', 'landlord', 'housing', 'apartment'],
        'Salary': ['salary', 'payment', 'wage', 'stipend', 'payroll', 'income'],
        'Hustle': ['freelance', 'gig', 'side', 'business', 'sale', 'commission'],
        'Transfer': ['transfer to', 'sent to', 'transferred to'],
        'Received': ['received from', 'credit from', 'deposit from'],
        'Shopping': ['shopping', 'purchase', 'buy', 'bought', 'mall', 'store', 'shop'],
        'Entertainment': ['movie', 'cinema', 'entertainment', 'event', 'ticket', 'show']
    }
    
    # Check for specific Moniepoint patterns
    if description.startswith('transfer to'):
        return 'Transfer'
    if description.startswith('received from'):
        return 'Received'
    if description.startswith('payment for'):
        # Try to determine what the payment was for
        payment_description = description.replace('payment for', '').strip()
        for category, keywords in category_keywords.items():
            for keyword in keywords:
                if keyword in payment_description:
                    return category
        # Default to Shopping if we can't determine
        return 'Shopping'
        
    # Regular categorization
    for category, keywords in category_keywords.items():
        for keyword in keywords:
            if keyword in description:
                return category
    
    return 'Other'  # Default category

if __name__ == '__main__':
    # For development only - use proper WSGI server in production
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000) 