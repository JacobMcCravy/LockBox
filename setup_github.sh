#!/bin/bash

# GitHub Setup Script for LockBox
# Run this from your LockBox-Portable-Complete directory

echo "🚀 Setting up LockBox for GitHub..."
echo "===================================="

# Create necessary directories
echo "Creating directories..."
mkdir -p .github/workflows
mkdir -p data
mkdir -p backups

# Create .gitkeep for empty directories
touch data/.gitkeep
touch backups/.gitkeep

# Create .gitignore
echo "Creating .gitignore..."
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
venv/
env/
ENV/
.venv

# Flask
instance/
.webassets-cache

# Environment variables - IMPORTANT: Contains encryption keys!
.env
.env.local
.env.*.local

# Database - Don't commit user data
data/*.db
data/*.sqlite
data/*.sqlite3
*.db
*.sqlite
*.sqlite3

# IDE
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store

# Testing
.coverage
htmlcov/
.pytest_cache/
.tox/

# Logs
*.log
logs/

# OS
Thumbs.db
.DS_Store

# Backups
backups/*.db
backups/*.env
*.backup
*.bak

# Docker
.dockerignore

# But DO include these:
!data/.gitkeep
!backups/.gitkeep
!.github/
EOF

# Create README.md
echo "Creating README.md..."
cat > README.md << 'EOF'
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

### Option 1: Setup Script
```bash
# Clone the repository
git clone https://github.com/JacobMcCravy/LockBox.git
cd LockBox

# Run setup script
chmod +x setup.sh
./setup.sh
```

### Option 2: Manual Setup
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

### Option 3: Docker
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
EOF

# Create GitHub Actions workflow
echo "Creating GitHub Actions workflow..."
cat > .github/workflows/tests.yml << 'EOF'
name: Tests

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        python-version: ['3.8', '3.9', '3.10', '3.11']

    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
    
    - name: Run tests
      run: |
        python test_lockbox.py
    
    - name: Test Flask app startup
      run: |
        # Start the app in background
        python app.py &
        APP_PID=$!
        
        # Wait for app to start
        sleep 5
        
        # Check if app is responding (Linux/Mac)
        if [[ "${{ matrix.os }}" != "windows-latest" ]]; then
          curl -f http://localhost:5001 || exit 1
        fi
        
        # Kill the app
        kill $APP_PID || true
      shell: bash
EOF

# Create test_lockbox.py if it doesn't exist
if [ ! -f "test_lockbox.py" ]; then
    echo "Creating test_lockbox.py..."
    cat > test_lockbox.py << 'EOF'
import os
import tempfile
import sqlite3
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash

# Test 1: Test Password Strength Validator
def test_password_strength():
    """Test the is_strong_password function"""
    print("Test 1: Testing password strength validator...")
    
    # Import the function from app.py
    from app import is_strong_password
    
    # Test weak passwords
    is_valid, msg = is_strong_password("short")
    assert is_valid == False, "Short password should fail"
    
    is_valid, msg = is_strong_password("alllowercase123!")
    assert is_valid == False, "Password without uppercase should fail"
    
    is_valid, msg = is_strong_password("ALLUPPERCASE123!")
    assert is_valid == False, "Password without lowercase should fail"
    
    is_valid, msg = is_strong_password("NoNumbers!")
    assert is_valid == False, "Password without numbers should fail"
    
    is_valid, msg = is_strong_password("NoSpecialChars123")
    assert is_valid == False, "Password without special characters should fail"
    
    # Test strong password
    is_valid, msg = is_strong_password("StrongPass123!")
    assert is_valid == True, "Strong password should pass"
    
    print("✓ Password strength tests passed!")


# Test 2: Test Database Creation
def test_database_creation():
    """Test that database tables are created correctly"""
    print("\nTest 2: Testing database creation...")
    
    # Create a temporary database
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        temp_db = tmp.name
    
    # Create connection and tables
    conn = sqlite3.connect(temp_db)
    conn.row_factory = sqlite3.Row
    
    # Create tables (simplified version of init_db)
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            username TEXT,
            password_encrypted BLOB NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    ''')
    conn.commit()
    
    # Test that tables exist
    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row['name'] for row in cursor.fetchall()]
    
    assert 'users' in tables, "Users table should exist"
    assert 'entries' in tables, "Entries table should exist"
    
    # Test inserting a user
    pw_hash = generate_password_hash("TestPassword123!")
    conn.execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                 ("testuser", "test@example.com", pw_hash))
    conn.commit()
    
    # Verify user was inserted
    cursor = conn.execute("SELECT * FROM users WHERE username = ?", ("testuser",))
    user = cursor.fetchone()
    assert user is not None, "User should be inserted"
    assert user['username'] == "testuser", "Username should match"
    
    conn.close()
    os.unlink(temp_db)  # Clean up
    
    print("✓ Database tests passed!")


# Test 3: Test Encryption/Decryption
def test_encryption():
    """Test that passwords are properly encrypted and decrypted"""
    print("\nTest 3: Testing encryption/decryption...")
    
    # Generate encryption key
    key = Fernet.generate_key()
    f = Fernet(key)
    
    # Test password
    original_password = "MySecretPassword123!"
    
    # Encrypt
    encrypted = f.encrypt(original_password.encode())
    assert encrypted != original_password.encode(), "Password should be encrypted"
    assert len(encrypted) > len(original_password), "Encrypted password should be longer"
    
    # Decrypt
    decrypted = f.decrypt(encrypted).decode()
    assert decrypted == original_password, "Decrypted password should match original"
    
    # Test with different passwords
    passwords = ["Test123!", "Another@Pass", "Complex$Pass123"]
    for pwd in passwords:
        encrypted = f.encrypt(pwd.encode())
        decrypted = f.decrypt(encrypted).decode()
        assert decrypted == pwd, f"Password {pwd} should encrypt/decrypt correctly"
    
    print("✓ Encryption tests passed!")


# Run all tests
if __name__ == "__main__":
    print("Running LockBox Tests...")
    print("=" * 40)
    
    try:
        test_password_strength()
        test_database_creation()
        test_encryption()
        
        print("\n" + "=" * 40)
        print("🎉 All tests passed!")
        
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        exit(1)
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        exit(1)
EOF
fi

echo ""
echo "✅ All files created successfully!"
echo ""
echo "📁 Created structure:"
find . -name ".git*" -prune -o -name "venv" -prune -o -name "__pycache__" -prune -o -type f -print | grep -E "(\.yml|\.md|\.gitignore|test_lockbox\.py)" | sort

echo ""
echo "📝 Next steps:"
echo "1. Review the files to make sure everything looks correct"
echo "2. Initialize Git and push to GitHub:"
echo ""
echo "   git init"
echo "   git add ."
echo "   git commit -m 'Initial commit: LockBox portable password manager'"
echo "   git remote add origin https://github.com/JacobMcCravy/LockBox.git"
echo "   git branch -M main"
echo "   git push -u origin main"
echo ""
echo "3. Check GitHub Actions at: https://github.com/JacobMcCravy/LockBox/actions"
echo ""
echo "Done! 🎉"
