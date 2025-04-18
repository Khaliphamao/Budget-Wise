import imaplib
from getpass import getpass

def test_imap_connection():
    """Test IMAP connection and mailbox selection."""
    print("Budget Wise - IMAP Connection Test")
    print("----------------------------------")
    
    # Get email credentials
    email_address = input("Enter your email address: ")
    password = getpass("Enter your email password: ")
    
    # Gmail is default, but can be changed
    imap_server = input("Enter IMAP server (default is imap.gmail.com): ") or "imap.gmail.com"
    
    print(f"Connecting to {imap_server}...")
    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(email_address, password)
        print("Login successful!")
        
        # Test mailbox selection
        print("Selecting inbox...")
        status, data = mail.select('inbox')
        print(f"Select status: {status}")
        
        if status == 'OK':
            print("Inbox selected successfully.")
            
            # Test basic search
            print("Attempting basic search...")
            search_status, search_data = mail.search(None, 'ALL')
            print(f"Search status: {search_status}")
            
            if search_status == 'OK':
                message_count = len(search_data[0].split())
                print(f"Search successful. Found {message_count} messages in inbox.")
            else:
                print("Search failed.")
        else:
            print(f"Failed to select inbox. Status: {status}")
        
        # Logout
        mail.logout()
        print("Logged out successfully.")
        
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    test_imap_connection() 