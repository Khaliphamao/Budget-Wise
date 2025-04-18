# Budget Wise

A personal finance management application that automatically categorizes transactions from bank email notifications.

## Features

- **Transaction Sync**: Automatically syncs transactions from bank email notifications
- **Transaction Categorization**: Intelligently categorizes transactions based on description
- **Financial Insights**: Track spending patterns and manage your budget effectively
- **Web Interface**: Easy-to-use web interface for managing your finances

## Getting Started

### Prerequisites

- Python 3.8 or higher
- SQLite database
- IMAP email account access

### Installation

1. Clone the repository:

   ```
   git clone https://github.com/your-username/budget-wise.git
   cd budget-wise
   ```

2. Install dependencies:

   ```
   pip install -r requirements.txt
   ```

3. Initialize the database:

   ```
   flask init-db
   ```

4. Run the application:
   ```
   flask run
   ```

## Email Configuration

For Gmail accounts, you need to:

1. Enable IMAP in Gmail settings
2. Use an app password instead of your regular password
3. Set up 2-factor authentication for your Google account

## Usage

1. Create an account or log in
2. Configure your email settings
3. Sync transactions from your email
4. View and manage your transactions
5. Analyze spending patterns

## Development

### Database Schema

The application uses an SQLite database with the following tables:

- `users`: User account information
- `transactions`: Transaction data synced from emails

### Testing Email Connectivity

You can test your IMAP connection with:

```
python test_imap_connection.py
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Thanks to all contributors
- Inspired by personal finance management needs
