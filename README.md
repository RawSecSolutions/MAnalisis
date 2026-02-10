# Gmail to Document Bot

Bot that fetches all emails from a specific sender in Gmail and exports them to Word (.docx) and/or PDF.

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Enable IMAP in Gmail

- Go to Gmail Settings > See all settings > Forwarding and POP/IMAP
- Enable IMAP Access
- Save Changes

### 3. Create a Gmail App Password

- Go to https://myaccount.google.com/apppasswords
- You need 2-Factor Authentication enabled on your Google account
- Select "Mail" as the app
- Copy the 16-character password generated

### 4. Configure credentials

```bash
cp .env.example .env
```

Edit `.env` with your Gmail address and the App Password from step 3.

## Usage

```bash
# Export all emails from a sender to both Word and PDF
python gmail_to_doc.py sender@example.com

# Export only to Word
python gmail_to_doc.py sender@example.com --format docx

# Export only to PDF
python gmail_to_doc.py sender@example.com --format pdf

# Custom output filename
python gmail_to_doc.py sender@example.com --output my_emails

# Search in all mail (not just inbox)
python gmail_to_doc.py sender@example.com --folder "[Gmail]/All Mail"
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `sender` | Email address to search for | (required) |
| `--format` | `docx`, `pdf`, or `both` | `both` |
| `--output` | Output filename (no extension) | `emails` |
| `--folder` | Gmail folder to search | `INBOX` |
