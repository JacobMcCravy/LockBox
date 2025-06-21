"""
test_lockbox_pytest.py
Automated Testing Suite for LockBox Password Manager
Uses pytest framework for automated testing
Tests core functionality: password validation, encryption, database operations, and user authentication
"""

import pytest
import tempfile
import os
import sqlite3
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash

# Import functions from our application
from app import is_strong_password, get_db, init_db, app


class TestPasswordStrength:
    """Test cases for password strength validation function"""
    
    def test_password_too_short(self):
        """Test that passwords under 8 characters are rejected"""
        is_valid, msg = is_strong_password("Short1!")
        assert is_valid == False
        assert "at least 8 characters" in msg
    
    def test_password_missing_uppercase(self):
        """Test that passwords without uppercase letters are rejected"""
        is_valid, msg = is_strong_password("alllowercase123!")
        assert is_valid == False
        assert "uppercase letter" in msg
    
    def test_password_missing_lowercase(self):
        """Test that passwords without lowercase letters are rejected"""
        is_valid, msg = is_strong_password("ALLUPPERCASE123!")
        assert is_valid == False
        assert "lowercase letter" in msg
    
    def test_password_missing_number(self):
        """Test that passwords without numbers are rejected"""
        is_valid, msg = is_strong_password("NoNumbersHere!")
        assert is_valid == False
        assert "number" in msg
    
    def test_password_missing_special_char(self):
        """Test that passwords without special characters are rejected"""
        is_valid, msg = is_strong_password("NoSpecialChars123")
        assert is_valid == False
        assert "special character" in msg
    
    def test_strong_password_accepted(self):
        """Test that a strong password meeting all requirements is accepted"""
        is_valid, msg = is_strong_password("StrongPass123!")
        assert is_valid == True
        assert msg == "Password is strong"


class TestEncryption:
    """Test cases for password encryption and decryption"""
    
    @pytest.fixture
    def fernet_key(self):
        """Fixture to provide a Fernet encryption key"""
        return Fernet.generate_key()
    
    def test_password_encryption(self, fernet_key):
        """Test that passwords are properly encrypted"""
        f = Fernet(fernet_key)
        original_password = "MySecretPassword123!"
        
        # Encrypt the password
        encrypted = f.encrypt(original_password.encode())
        
        # Verify it's encrypted (not the same as original)
        assert encrypted != original_password.encode()
        assert len(encrypted) > len(original_password)
        
    def test_password_decryption(self, fernet_key):
        """Test that encrypted passwords can be decrypted correctly"""
        f = Fernet(fernet_key)
        original_password = "TestPassword@456"
        
        # Encrypt then decrypt
        encrypted = f.encrypt(original_password.encode())
        decrypted = f.decrypt(encrypted).decode()
        
        # Verify decryption returns original
        assert decrypted == original_password
    
    def test_multiple_passwords_encryption(self, fernet_key):
        """Test encryption/decryption of multiple different passwords"""
        f = Fernet(fernet_key)
        test_passwords = [
            "SimplePass123!",
            "C0mpl3x@P@ssw0rd",
            "Another$ecure1",
            "Test#Pass2023"
        ]
        
        for password in test_passwords:
            encrypted = f.encrypt(password.encode())
            decrypted = f.decrypt(encrypted).decode()
            assert decrypted == password
            assert encrypted != password.encode()


class TestDatabaseOperations:
    """Test cases for database operations"""
    
    @pytest.fixture
    def temp_db(self):
        """Fixture to provide a temporary database for testing"""
        # Create temporary database file
        db_fd, db_path = tempfile.mkstemp()
        
        # Initialize database with our schema
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                display_name TEXT DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL
            );

            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                folder_id INTEGER DEFAULT NULL,
                title TEXT NOT NULL,
                username TEXT,
                password_encrypted BLOB NOT NULL,
                url TEXT,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                color TEXT DEFAULT '#3b82f6',
                icon TEXT DEFAULT 'folder',
                parent_id INTEGER DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (parent_id) REFERENCES folders(id) ON DELETE CASCADE,
                UNIQUE(user_id, name)
            );
        ''')
        conn.commit()
        conn.close()
        
        yield db_path
        
        # Cleanup
        os.close(db_fd)
        os.unlink(db_path)
    
    def test_database_tables_created(self, temp_db):
        """Test that all required database tables are created"""
        conn = sqlite3.connect(temp_db)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        # Verify all tables exist
        assert 'users' in tables
        assert 'entries' in tables
        assert 'folders' in tables
    
    def test_user_creation(self, temp_db):
        """Test creating a new user in the database"""
        conn = sqlite3.connect(temp_db)
        conn.row_factory = sqlite3.Row
        
        # Create a test user
        username = "testuser"
        email = "test@example.com"
        password_hash = generate_password_hash("TestPassword123!")
        
        conn.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash)
        )
        conn.commit()
        
        # Verify user was created
        cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        assert user is not None
        assert user['username'] == username
        assert user['email'] == email
        assert user['id'] == 1
        
        conn.close()
    
    def test_password_entry_creation(self, temp_db):
        """Test creating a password entry in the database"""
        conn = sqlite3.connect(temp_db)
        conn.row_factory = sqlite3.Row
        
        # First create a user
        user_id = conn.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            ("testuser", "test@example.com", generate_password_hash("Test123!"))
        ).lastrowid
        
        # Create encryption key and encrypt a password
        f = Fernet(Fernet.generate_key())
        encrypted_password = f.encrypt("MySecretPassword".encode())
        
        # Create password entry
        entry_data = {
            'user_id': user_id,
            'title': 'Test Website',
            'username': 'myusername',
            'password_encrypted': encrypted_password,
            'url': 'https://example.com',
            'notes': 'Test notes for this entry'
        }
        
        cursor = conn.execute(
            """INSERT INTO entries (user_id, title, username, password_encrypted, url, notes) 
               VALUES (?, ?, ?, ?, ?, ?)""",
            (entry_data['user_id'], entry_data['title'], entry_data['username'],
             entry_data['password_encrypted'], entry_data['url'], entry_data['notes'])
        )
        entry_id = cursor.lastrowid
        conn.commit()
        
        # Verify entry was created
        cursor = conn.execute("SELECT * FROM entries WHERE id = ?", (entry_id,))
        entry = cursor.fetchone()
        
        assert entry is not None
        assert entry['title'] == 'Test Website'
        assert entry['username'] == 'myusername'
        assert entry['url'] == 'https://example.com'
        assert entry['notes'] == 'Test notes for this entry'
        assert entry['user_id'] == user_id
        
        conn.close()
    
    def test_duplicate_username_rejected(self, temp_db):
        """Test that duplicate usernames are rejected"""
        conn = sqlite3.connect(temp_db)
        
        # Create first user
        conn.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            ("duplicate_user", "first@example.com", generate_password_hash("Test123!"))
        )
        conn.commit()
        
        # Try to create second user with same username
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                ("duplicate_user", "second@example.com", generate_password_hash("Test456!"))
            )
        
        conn.close()


class TestUserAuthentication:
    """Test cases for user authentication"""
    
    def test_password_hash_verification(self):
        """Test that password hashing and verification works correctly"""
        original_password = "MySecurePassword123!"
        
        # Generate hash
        password_hash = generate_password_hash(original_password)
        
        # Verify correct password
        assert check_password_hash(password_hash, original_password) == True
        
        # Verify wrong password fails
        assert check_password_hash(password_hash, "WrongPassword123!") == False
    
    def test_different_passwords_different_hashes(self):
        """Test that different passwords produce different hashes"""
        password1 = "FirstPassword123!"
        password2 = "SecondPassword456!"
        
        hash1 = generate_password_hash(password1)
        hash2 = generate_password_hash(password2)
        
        # Hashes should be different
        assert hash1 != hash2
        
        # Each password should only verify with its own hash
        assert check_password_hash(hash1, password1) == True
        assert check_password_hash(hash1, password2) == False
        assert check_password_hash(hash2, password2) == True
        assert check_password_hash(hash2, password1) == False
    
    def test_same_password_different_hashes(self):
        """Test that same password generates different hashes (due to salt)"""
        password = "SamePassword123!"
        
        hash1 = generate_password_hash(password)
        hash2 = generate_password_hash(password)
        
        # Hashes should be different due to salt
        assert hash1 != hash2
        
        # But both should verify with the original password
        assert check_password_hash(hash1, password) == True
        assert check_password_hash(hash2, password) == True


# Test runner for when script is run directly
if __name__ == "__main__":
    # Run pytest with verbose output
    pytest.main([__file__, "-v", "--tb=short"])
