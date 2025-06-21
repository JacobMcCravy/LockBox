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
        print("All tests passed!")
        
    except AssertionError as e:
        print(f"\nTest failed: {e}")
        exit(1)
    except Exception as e:
        print(f"\nError during testing: {e}")
        exit(1)
