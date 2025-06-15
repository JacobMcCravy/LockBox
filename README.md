# LockBox - Portable Password Manager

[![Tests](https://github.com/JacobMcCravy/LockBox/actions/workflows/tests.yml/badge.svg)](https://github.com/JacobMcCravy/LockBox/actions/workflows/tests.yml)

A secure, portable password manager that works on Windows, Mac, and Linux. No database server required - just Python and SQLite.

## Features

- Secure encryption using Fernet/AES
- Portable SQLite database - no server needed
- Folder system for organizing passwords
- Cross-platform - works on Windows, Mac, and Linux
- Simple one-command setup
- Clean, modern web interface

## Quick Start

### Option 1: Manual Setup
```bash
# Clone the repository
git clone https://github.com/JacobMcCravy/LockBox.git
cd LockBox

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Mac/Linux:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

### Option 2: Docker
```bash
docker compose up -d
```

Access the application at http://localhost:5001

## First Time Use

1. Open your browser to http://localhost:5001
2. Click "Register" to create an account
3. Choose a strong master password
4. Start adding your passwords

## Running Tests

```bash
# Activate virtual environment first
source venv/bin/activate  # Mac/Linux
# or
venv\Scripts\activate     # Windows

# Run tests
python test_lockbox.py
```

## Project Structure

```
lockbox/
├── app.py              # Main Flask application
├── test_lockbox.py     # Test suite
├── requirements.txt    # Python dependencies
├── setup.sh           # Easy setup script
├── Dockerfile         # Docker configuration
├── docker-compose.yml # Docker Compose config
├── static/            # CSS, JS, images
├── templates/         # HTML templates
└── data/             # SQLite database (created on first run)
```

## Security

- Passwords are encrypted using Fernet (symmetric encryption)
- Encryption keys are generated automatically and stored in .env
- SQLite database stores only encrypted data
- Strong password requirements enforced

**Important**: Always backup your .env file - without it, you cannot decrypt your passwords.

## Backup

To backup your passwords:
```bash
cp data/lockbox.db backups/lockbox_$(date +%Y%m%d).db
cp .env backups/.env_backup
```
