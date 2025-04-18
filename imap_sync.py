import imaplib
import email
import re
import sqlite3
import datetime
from datetime import timedelta
from email.header import decode_header
import os
from getpass import getpass

def connect_to_imap(email_address, password, imap_server="imap.gmail.com"):
    """Connect to IMAP server and return mail object."""
    print(f"Connecting to {imap_server}...")
    mail = imaplib.IMAP4_SSL(imap_server)
    
    try:
        mail.login(email_address, password)
        print("Login successful!")
        return mail
    except Exception as e:
        print(f"Login failed: {e}")
        return None

def get_bank_senders():
    """Get list of bank email senders."""
    return {
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
    }

def search_emails(mail, days=90):
    """Search for bank transaction emails."""
    senders = get_bank_senders()
    
    # Select inbox FIRST - before any search commands
    mail.select('inbox')
    
    # Create search query for all bank senders - in a more compatible format
    search_criteria = []
    for sender in senders.values():
        # Use a simpler search format that's more widely compatible
        status, email_ids = mail.search(None, f'FROM "{sender}"')
        if status == 'OK' and email_ids[0]:
            search_criteria.extend(email_ids[0].split())
    
    # Get date for filtering
    cutoff_date = datetime.datetime.now() - timedelta(days=days)
    
    print(f"Found {len(search_criteria)} potential emails before date filtering")
    
    # Filter by date after fetching emails (instead of in the IMAP query)
    filtered_emails = []
    for email_id in search_criteria:
        try:
            # Get email headers
            status, email_data = mail.fetch(email_id, '(BODY.PEEK[HEADER.FIELDS (DATE)])')
            if status != 'OK':
                continue
                
            header_data = email_data[0][1].decode('utf-8')
            date_str = header_data.split('Date:')[-1].strip()
            
            # Try to parse the date
            try:
                # Try various date formats
                for fmt in ['%a, %d %b %Y %H:%M:%S %z', '%a, %d %b %Y %H:%M:%S', '%d %b %Y %H:%M:%S %z']:
                    try:
                        email_date = datetime.datetime.strptime(date_str, fmt)
                        break
                    except ValueError:
                        continue
                else:  # If none of the formats matched
                    # Use a more forgiving approach - just extract the year and month
                    import re
                    match = re.search(r'(\d{1,2})\s+(\w{3})\s+(\d{4})', date_str)
                    if match:
                        day, month, year = match.groups()
                        months = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6, 
                                  'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}
                        email_date = datetime.datetime(int(year), months.get(month, 1), int(day))
                    else:
                        # If all else fails, assume it's recent
                        email_date = datetime.datetime.now()
            except Exception:
                # Default to current date if parsing fails
                email_date = datetime.datetime.now()
            
            # Check if the email is within our date range
            if email_date >= cutoff_date:
                filtered_emails.append(email_id)
        except Exception as e:
            print(f"Error processing email {email_id}: {str(e)}")
    
    print(f"Found {len(filtered_emails)} emails matching search criteria after date filtering")
    return filtered_emails

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
    
    # If amount not found, try a fallback for common formats
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
    
    # If no date found, use the email date
    if 'date' not in transaction:
        transaction['date'] = datetime.date.today()
    
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

def fetch_and_process_emails(mail, user_id):
    """Fetch emails and process transactions."""
    email_ids = search_emails(mail)
    
    if not email_ids:
        print("No matching emails found.")
        return 0
    
    # Connect to database
    conn = sqlite3.connect('instance/budgetwise.db')
    cursor = conn.cursor()
    
    # Check existing email_ids to avoid duplicates
    cursor.execute('SELECT email_id FROM transactions WHERE user_id = ?', (user_id,))
    existing_email_ids = [row[0] for row in cursor.fetchall()]
    
    transaction_count = 0
    credit_keywords = ['Credit', 'received', 'deposit', 'inflow']
    debit_keywords = ['Debit', 'purchase', 'withdrawal', 'transfer', 'payment']
    
    # Process each email
    for email_id in email_ids:
        # Ensure email_id is valid
        if not email_id:
            print("Skipping invalid email ID")
            continue
            
        if isinstance(email_id, bytes):
            email_id_str = email_id.decode()
        else:
            email_id_str = str(email_id)
        
        # Skip if already processed
        if email_id_str in existing_email_ids:
            print(f"Email {email_id_str} already processed, skipping...")
            continue
        
        try:
            # Fetch email
            status, email_data = mail.fetch(email_id, '(RFC822)')
            if status != 'OK' or not email_data or not email_data[0]:
                print(f"Failed to fetch email {email_id_str}")
                continue
            
            # Parse email
            raw_email = email_data[0][1]
            msg = email.message_from_bytes(raw_email)
            
            # Get subject and sender
            subject = "No Subject"
            try:
                subject_header = decode_header(msg.get('Subject', ''))
                if subject_header and subject_header[0]:
                    subject, encoding = subject_header[0]
                    if isinstance(subject, bytes):
                        subject = subject.decode(encoding or 'utf-8')
            except Exception as e:
                print(f"Error decoding subject: {e}")
            
            sender = msg.get('From', 'Unknown Sender')
            
            # Get email date with fallback
            email_date = datetime.datetime.now().date()
            try:
                date_str = msg.get('Date', '')
                for fmt in ['%a, %d %b %Y %H:%M:%S %z', '%a, %d %b %Y %H:%M:%S', '%d %b %Y %H:%M:%S %z']:
                    try:
                        email_date = datetime.datetime.strptime(date_str, fmt).date()
                        break
                    except ValueError:
                        continue
            except Exception as e:
                print(f"Error parsing email date: {e}")
            
            # Extract body with proper type handling
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition", ""))
                    
                    if content_type == "text/plain" and "attachment" not in content_disposition:
                        try:
                            # This will return bytes for binary payloads
                            payload = part.get_payload(decode=True)
                            if payload is not None:
                                if isinstance(payload, bytes):
                                    try:
                                        body = payload.decode('utf-8')
                                    except UnicodeDecodeError:
                                        body = payload.decode('iso-8859-1')
                                elif isinstance(payload, str):
                                    body = payload
                                else:
                                    body = str(payload)
                            break
                        except Exception as e:
                            print(f"Error extracting multipart body: {e}")
            else:
                # Not multipart
                try:
                    # This will return bytes for binary payloads
                    payload = msg.get_payload(decode=True)
                    if payload is not None:
                        if isinstance(payload, bytes):
                            try:
                                body = payload.decode('utf-8')
                            except UnicodeDecodeError:
                                body = payload.decode('iso-8859-1')
                        elif isinstance(payload, str):
                            body = payload
                        else:
                            body = str(payload)
                except Exception as e:
                    print(f"Error extracting body: {e}")
            
            print(f"Processing email from: {sender}")
            print(f"Subject: {subject}")
            
            # Parse transaction
            transaction = parse_transaction_email(body, subject, sender)
            
            if transaction:
                # Get transaction date from email if not extracted from body
                if not transaction.get('date'):
                    transaction['date'] = email_date
                
                # Determine transaction type based on keywords
                transaction_type = 'expense'  # Default
                description = transaction.get('description', '').lower()
                
                # Check for income keywords
                for keyword in credit_keywords:
                    if keyword.lower() in description:
                        transaction_type = 'income'
                        break
                
                # Check for expense keywords that override
                for keyword in debit_keywords:
                    if keyword.lower() in description:
                        transaction_type = 'expense'
                        break
                
                # Determine category based on keywords
                category = categorize_transaction(transaction.get('description', ''))
                
                # Insert into database
                cursor.execute('''
                    INSERT INTO transactions 
                    (user_id, amount, description, category, transaction_type, transaction_date, email_id, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    user_id,
                    transaction.get('amount', 0),
                    transaction.get('description', 'Unknown transaction'),
                    category,
                    transaction_type,
                    transaction.get('date'),
                    email_id_str,
                    datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                ))
                
                transaction_count += 1
                print(f"Added transaction: {transaction.get('description')} - {transaction.get('amount')}")
        except Exception as e:
            print(f"Error processing email {email_id_str}: {str(e)}")
    
    # Commit changes
    conn.commit()
    
    # Close database connection
    conn.close()
    
    return transaction_count

def main():
    """Main function to run the IMAP transaction sync."""
    print("Budget Wise - IMAP Transaction Sync")
    print("-----------------------------------")
    
    # Get user ID
    user_id = int(input("Enter your user ID: "))
    
    # Get email credentials
    email_address = input("Enter your email address: ")
    password = getpass("Enter your email password: ")
    
    # Gmail is default, but can be changed
    imap_server = input("Enter IMAP server (default is imap.gmail.com): ") or "imap.gmail.com"
    
    # Connect to IMAP
    mail = connect_to_imap(email_address, password, imap_server)
    if not mail:
        print("Failed to connect to email server. Please check your credentials.")
        return
    
    # Fetch and process emails
    transaction_count = fetch_and_process_emails(mail, user_id)
    
    # Log out
    mail.logout()
    
    print(f"\nSync completed. Added {transaction_count} new transactions.")

if __name__ == "__main__":
    main() 