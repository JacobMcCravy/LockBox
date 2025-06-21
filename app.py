import os
import sqlite3
from flask import Flask, render_template, redirect, url_for, request, flash, g
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import re
from datetime import timedelta, datetime
import secrets
import string

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Generate secret key if not exists
if not os.getenv('SECRET_KEY'):
    with open('.env', 'a') as f:
        f.write(f"\nSECRET_KEY={secrets.token_hex(32)}")
    load_dotenv()

# Generate encryption key if not exists
if not os.getenv('ENCRYPTION_KEY'):
    key = Fernet.generate_key().decode()
    with open('.env', 'a') as f:
        f.write(f"\nENCRYPTION_KEY={key}")
    load_dotenv()

app.secret_key = os.getenv('SECRET_KEY')
app.permanent_session_lifetime = timedelta(minutes=30)

# Database configuration
DATABASE = os.getenv('DATABASE_PATH', 'lockbox.db')

# Encryption setup
f = Fernet(os.getenv('ENCRYPTION_KEY').encode())

# Database helper functions
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize the database with tables"""
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP NULL
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
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
        );

        CREATE INDEX IF NOT EXISTS idx_user_parent ON folders(user_id, parent_id);
        CREATE INDEX IF NOT EXISTS idx_user_created ON entries(user_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_folder ON entries(folder_id);
    ''')
    db.commit()

# Initialize database on first run
with app.app_context():
    init_db()

# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

class User(UserMixin):
    def __init__(self, id, username, email, pw_hash):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = pw_hash

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    cur = db.execute("SELECT * FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    return User(row['id'], row['username'], row['email'], row['password_hash']) if row else None

# Password strength validator
def is_strong_password(password):
    """Check if password meets minimum requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    return True, "Password is strong"

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        uname = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        pwd = request.form.get('password', '')
        confirm_pwd = request.form.get('confirm_password', '')
        
        if not email:
            email = ''
        
        if not uname or not pwd:
            flash('Username and password are required.', 'error')
            return render_template('register.html')
        
        if pwd != confirm_pwd:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        is_strong, msg = is_strong_password(pwd)
        if not is_strong:
            flash(msg, 'error')
            return render_template('register.html')
        
        if email and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            flash('Please enter a valid email address.', 'error')
            return render_template('register.html')
        
        pw_hash = generate_password_hash(pwd)
        db = get_db()
        
        try:
            db.execute("INSERT INTO users (username, email, password_hash) VALUES (?,?,?)", 
                      (uname, email, pw_hash))
            db.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already taken.', 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        login_input = request.form.get('username', '').strip()
        pwd = request.form.get('password', '')
        
        if not login_input or not pwd:
            flash('Please enter your username/email and password.', 'error')
            return render_template('login.html')
        
        db = get_db()
        
        # Check if input looks like an email
        is_email_input = '@' in login_input
        
        if is_email_input:
            cur = db.execute("SELECT * FROM users WHERE email=?", (login_input,))
        else:
            cur = db.execute("SELECT * FROM users WHERE username=?", (login_input,))
        
        user = cur.fetchone()
        
        # If not found, try the opposite
        if not user:
            if is_email_input:
                cur = db.execute("SELECT * FROM users WHERE username=?", (login_input,))
            else:
                cur = db.execute("SELECT * FROM users WHERE email=?", (login_input,))
            user = cur.fetchone()
        
        if user and check_password_hash(user['password_hash'], pwd):
            display_name = user['display_name'] or user['username']
            
            # Update last login
            db.execute("UPDATE users SET last_login = ? WHERE id = ?", 
                      (datetime.now(), user['id']))
            db.commit()
            
            login_user(User(user['id'], user['username'], user['email'], user['password_hash']), 
                      remember=True)
            flash(f'Welcome back, {display_name}!', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Invalid username/email or password.', 'error')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    
    # Get selected folder from query parameter
    selected_folder_id = request.args.get('folder', type=int)
    
    # Get display name
    cur = db.execute("SELECT display_name FROM users WHERE id = ?", (current_user.id,))
    result = cur.fetchone()
    display_name = result['display_name'] if result and result['display_name'] else current_user.username
    
    # Get primary folders with entry counts
    cur = db.execute("""
        SELECT f.*, COUNT(e.id) as total_count 
        FROM folders f 
        LEFT JOIN entries e ON f.id = e.folder_id 
        WHERE f.user_id = ? AND f.parent_id IS NULL
        GROUP BY f.id 
        ORDER BY f.name
    """, (current_user.id,))
    primary_folders = [dict(row) for row in cur.fetchall()]
    
    # Get ALL folders for move dialog
    cur = db.execute("""
        SELECT f.*, COUNT(e.id) as total_count 
        FROM folders f 
        LEFT JOIN entries e ON f.id = e.folder_id 
        WHERE f.user_id = ?
        GROUP BY f.id 
        ORDER BY f.name
    """, (current_user.id,))
    all_folders = [dict(row) for row in cur.fetchall()]
    
    # Initialize variables
    current_folder = None
    subfolders = []
    breadcrumbs = []
    
    # If a folder is selected, get its info and subfolders
    if selected_folder_id and selected_folder_id != 0:
        cur = db.execute("SELECT * FROM folders WHERE id = ? AND user_id = ?", 
                        (selected_folder_id, current_user.id))
        current_folder = cur.fetchone()
        
        if current_folder:
            current_folder = dict(current_folder)
            
            # Get subfolders
            cur = db.execute("""
                SELECT f.*, COUNT(e.id) as total_count
                FROM folders f
                LEFT JOIN entries e ON f.id = e.folder_id
                WHERE f.parent_id = ? AND f.user_id = ?
                GROUP BY f.id
                ORDER BY f.name
            """, (selected_folder_id, current_user.id))
            subfolders = [dict(row) for row in cur.fetchall()]
            
            # Build breadcrumbs
            parent_id = current_folder['parent_id']
            breadcrumbs = [current_folder]
            while parent_id:
                cur = db.execute("SELECT * FROM folders WHERE id = ?", (parent_id,))
                parent = cur.fetchone()
                if parent:
                    parent = dict(parent)
                    breadcrumbs.insert(0, parent)
                    parent_id = parent['parent_id']
                else:
                    break
    
    # Get entries based on folder selection
    if selected_folder_id is not None:
        if selected_folder_id == 0:
            # Show unorganized entries
            cur = db.execute("SELECT * FROM entries WHERE user_id=? AND folder_id IS NULL ORDER BY id DESC", 
                           (current_user.id,))
        else:
            # Show entries from specific folder
            cur = db.execute("SELECT * FROM entries WHERE user_id=? AND folder_id=? ORDER BY id DESC", 
                           (current_user.id, selected_folder_id))
    else:
        # Show all entries
        cur = db.execute("SELECT * FROM entries WHERE user_id=? ORDER BY id DESC", (current_user.id,))
    
    entries = [dict(row) for row in cur.fetchall()]
    
    # Get counts
    cur = db.execute("SELECT COUNT(*) as count FROM entries WHERE user_id=? AND folder_id IS NULL", 
                    (current_user.id,))
    unorganized_count = cur.fetchone()['count']
    
    cur = db.execute("SELECT COUNT(*) as count FROM entries WHERE user_id=?", (current_user.id,))
    total_entries = cur.fetchone()['count']
    
    # Decrypt passwords
    for e in entries:
        try:
            e['password'] = f.decrypt(e['password_encrypted']).decode()
        except:
            e['password'] = "Error decrypting"
    
    return render_template('dashboard.html', 
                         entries=entries, 
                         primary_folders=primary_folders,
                         subfolders=subfolders,
                         all_folders=all_folders,
                         current_folder=current_folder,
                         breadcrumbs=breadcrumbs,
                         selected_folder_id=selected_folder_id,
                         unorganized_count=unorganized_count,
                         total_entries=total_entries,
                         username=display_name)

@app.route('/add', methods=['GET','POST'])
@login_required
def add_entry():
    db = get_db()
    
    # Get folder_id from query parameter
    default_folder_id = request.args.get('folder_id', type=int)
    
    # Get folders for dropdown
    cur = db.execute("SELECT * FROM folders WHERE user_id=? ORDER BY name", (current_user.id,))
    folders = [dict(row) for row in cur.fetchall()]
    
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        url = request.form.get('url', '').strip()
        notes = request.form.get('notes', '').strip()
        folder_id = request.form.get('folder_id', type=int) or default_folder_id
        
        if not title or not username or not password:
            flash('Title, username, and password are required.', 'error')
            return render_template('add_entry.html', folders=folders, default_folder_id=default_folder_id)
        
        encrypted = f.encrypt(password.encode())
        
        db.execute(
            "INSERT INTO entries (user_id,title,username,password_encrypted,url,notes,folder_id) VALUES (?,?,?,?,?,?,?)",
            (current_user.id, title, username, encrypted, url, notes, folder_id)
        )
        db.commit()
        
        flash('Entry added successfully!', 'success')
        
        if folder_id:
            return redirect(url_for('dashboard', folder=folder_id))
        return redirect(url_for('dashboard'))
    
    return render_template('add_entry.html', folders=folders, default_folder_id=default_folder_id)

@app.route('/edit/<int:id>', methods=['GET','POST'])
@login_required
def edit_entry(id):
    db = get_db()
    
    # Get folders
    cur = db.execute("SELECT * FROM folders WHERE user_id=? ORDER BY name", (current_user.id,))
    folders = [dict(row) for row in cur.fetchall()]
    
    # Get the entry
    cur = db.execute("SELECT * FROM entries WHERE id=? AND user_id=?", (id, current_user.id))
    entry = cur.fetchone()
    
    if not entry:
        flash('Entry not found.', 'error')
        return redirect(url_for('dashboard'))
    
    entry = dict(entry)
    
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        url = request.form.get('url', '').strip()
        notes = request.form.get('notes', '').strip()
        folder_id = request.form.get('folder_id', type=int)
        
        if not title or not username or not password:
            flash('Title, username, and password are required.', 'error')
            return render_template('edit_entry.html', entry=entry, folders=folders)
        
        encrypted = f.encrypt(password.encode())
        
        db.execute(
            "UPDATE entries SET title=?,username=?,password_encrypted=?,url=?,notes=?,folder_id=?,updated_at=? WHERE id=?",
            (title, username, encrypted, url, notes, folder_id if folder_id else None, datetime.now(), id)
        )
        db.commit()
        
        flash('Entry updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    try:
        entry['password'] = f.decrypt(entry['password_encrypted']).decode()
    except:
        entry['password'] = ""
    
    return render_template('edit_entry.html', entry=entry, folders=folders)

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_entry(id):
    db = get_db()
    cur = db.execute("DELETE FROM entries WHERE id=? AND user_id=?", (id, current_user.id))
    db.commit()
    
    if cur.rowcount:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return {'success': True}
        flash('Entry deleted successfully!', 'success')
    else:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return {'success': False}
        flash('Entry not found.', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/generate-password')
@login_required
def generate_password():
    length = 16
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return {'password': password}

@app.route('/create-folder', methods=['POST'])
@login_required
def create_folder():
    data = request.get_json()
    folder_name = data.get('name', '').strip()
    parent_id = data.get('parent_id')
    color = data.get('color', '#3b82f6')
    
    if not folder_name:
        return {'success': False, 'message': 'Folder name is required'}
    
    if not re.match(r'^#[0-9A-Fa-f]{6}$', color):
        color = '#3b82f6'
    
    db = get_db()
    try:
        if parent_id:
            # Verify parent folder belongs to user
            cur = db.execute("SELECT id FROM folders WHERE id = ? AND user_id = ?", 
                           (parent_id, current_user.id))
            if not cur.fetchone():
                return {'success': False, 'message': 'Parent folder not found'}
        
        db.execute("""
            INSERT INTO folders (user_id, name, color, icon, parent_id) 
            VALUES (?, ?, ?, 'folder', ?)
        """, (current_user.id, folder_name, color, parent_id))
        db.commit()
        
        return {'success': True}
    except sqlite3.IntegrityError:
        return {'success': False, 'message': 'A folder with this name already exists'}
    except Exception as e:
        return {'success': False, 'message': str(e)}

@app.route('/folder-info/<int:folder_id>')
@login_required
def folder_info(folder_id):
    db = get_db()
    
    # Check if folder belongs to user
    cur = db.execute("SELECT name FROM folders WHERE id = ? AND user_id = ?", 
                    (folder_id, current_user.id))
    folder = cur.fetchone()
    
    if not folder:
        return {'success': False, 'message': 'Folder not found'}
    
    # Get all subfolder IDs recursively
    def get_all_subfolder_ids(parent_id):
        cur = db.execute("SELECT id FROM folders WHERE parent_id = ? AND user_id = ?", 
                        (parent_id, current_user.id))
        subfolder_ids = [row['id'] for row in cur.fetchall()]
        all_ids = subfolder_ids.copy()
        
        for subfolder_id in subfolder_ids:
            all_ids.extend(get_all_subfolder_ids(subfolder_id))
        
        return all_ids
    
    # Get counts
    cur = db.execute("SELECT COUNT(*) as count FROM folders WHERE parent_id = ? AND user_id = ?", 
                    (folder_id, current_user.id))
    direct_subfolder_count = cur.fetchone()['count']
    
    all_folder_ids = [folder_id] + get_all_subfolder_ids(folder_id)
    
    placeholders = ','.join(['?' for _ in all_folder_ids])
    cur = db.execute(f"SELECT COUNT(*) as count FROM entries WHERE folder_id IN ({placeholders})", 
                    all_folder_ids)
    entry_count = cur.fetchone()['count']
    
    return {
        'success': True,
        'name': folder['name'],
        'subfolder_count': len(all_folder_ids) - 1,
        'direct_subfolder_count': direct_subfolder_count,
        'entry_count': entry_count
    }

@app.route('/delete-folder/<int:folder_id>', methods=['POST'])
@login_required
def delete_folder(folder_id):
    db = get_db()
    
    # Check if folder belongs to user
    cur = db.execute("SELECT name FROM folders WHERE id = ? AND user_id = ?", 
                    (folder_id, current_user.id))
    folder = cur.fetchone()
    
    if not folder:
        return {'success': False, 'message': 'Folder not found'}
    
    # Get all subfolder IDs recursively
    def get_all_subfolder_ids(parent_id):
        cur = db.execute("SELECT id FROM folders WHERE parent_id = ? AND user_id = ?", 
                        (parent_id, current_user.id))
        subfolder_ids = [row['id'] for row in cur.fetchall()]
        all_ids = subfolder_ids.copy()
        
        for subfolder_id in subfolder_ids:
            all_ids.extend(get_all_subfolder_ids(subfolder_id))
        
        return all_ids
    
    all_folder_ids = [folder_id] + get_all_subfolder_ids(folder_id)
    
    # Check if any folders contain entries
    placeholders = ','.join(['?' for _ in all_folder_ids])
    cur = db.execute(f"SELECT COUNT(*) as total_entries FROM entries WHERE folder_id IN ({placeholders})", 
                    all_folder_ids)
    entry_count = cur.fetchone()['total_entries']
    
    if entry_count > 0:
        return {
            'success': False, 
            'message': f'Cannot delete folder "{folder["name"]}". It or its subfolders contain {entry_count} entries. Move or delete all entries first.'
        }
    
    # Delete all folders
    all_folder_ids.reverse()
    for fid in all_folder_ids:
        db.execute("DELETE FROM folders WHERE id = ? AND user_id = ?", (fid, current_user.id))
    
    db.commit()
    
    return {
        'success': True,
        'message': f'Successfully deleted {len(all_folder_ids)} folder(s)'
    }

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    db = get_db()
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_display_name':
            display_name = request.form.get('display_name', '').strip()
            if display_name:
                db.execute("UPDATE users SET display_name = ? WHERE id = ?", 
                          (display_name, current_user.id))
                db.commit()
                flash('Display name updated successfully!', 'success')
            
        elif action == 'change_password':
            current_pwd = request.form.get('current_password', '')
            new_pwd = request.form.get('new_password', '')
            confirm_pwd = request.form.get('confirm_password', '')
            
            # Verify current password
            cur = db.execute("SELECT password_hash FROM users WHERE id = ?", (current_user.id,))
            user = cur.fetchone()
            
            if not check_password_hash(user['password_hash'], current_pwd):
                flash('Current password is incorrect.', 'error')
            elif new_pwd != confirm_pwd:
                flash('New passwords do not match.', 'error')
            else:
                is_strong, msg = is_strong_password(new_pwd)
                if not is_strong:
                    flash(msg, 'error')
                else:
                    new_hash = generate_password_hash(new_pwd)
                    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", 
                              (new_hash, current_user.id))
                    db.commit()
                    flash('Password changed successfully!', 'success')
    
    # Get current display name
    cur = db.execute("SELECT display_name FROM users WHERE id = ?", (current_user.id,))
    result = cur.fetchone()
    display_name = result['display_name'] if result and result['display_name'] else None
    
    return render_template('settings.html', 
                         username=current_user.username,
                         display_name=display_name or current_user.username)

@app.route('/move-entry/<int:entry_id>', methods=['POST'])
@login_required
def move_entry(entry_id):
    data = request.get_json()
    folder_id = data.get('folder_id')
    
    db = get_db()
    
    # Verify entry belongs to user
    cur = db.execute("SELECT id FROM entries WHERE id = ? AND user_id = ?", 
                    (entry_id, current_user.id))
    if not cur.fetchone():
        return {'success': False, 'message': 'Entry not found'}
    
    # Update entry's folder
    db.execute("UPDATE entries SET folder_id = ? WHERE id = ? AND user_id = ?", 
              (folder_id, entry_id, current_user.id))
    db.commit()
    
    return {'success': True}

@app.route('/delete-account', methods=['POST'])
@login_required
def delete_account():
    data = request.get_json()
    password = data.get('password', '')
    confirm_text = data.get('confirm_text', '')
    
    if confirm_text != 'DELETE MY ACCOUNT':
        return {'success': False, 'message': 'Please type the confirmation text exactly as shown'}
    
    db = get_db()
    
    # Verify password
    cur = db.execute("SELECT password_hash FROM users WHERE id = ?", (current_user.id,))
    user = cur.fetchone()
    
    if not user or not check_password_hash(user['password_hash'], password):
        return {'success': False, 'message': 'Incorrect password'}
    
    # Get statistics
    cur = db.execute("SELECT COUNT(*) as count FROM entries WHERE user_id = ?", (current_user.id,))
    entry_count = cur.fetchone()['count']
    
    cur = db.execute("SELECT COUNT(*) as count FROM folders WHERE user_id = ?", (current_user.id,))
    folder_count = cur.fetchone()['count']
    
    # Delete the user (CASCADE will handle entries and folders)
    db.execute("DELETE FROM users WHERE id = ?", (current_user.id,))
    db.commit()
    
    logout_user()
    
    return {
        'success': True,
        'message': f'Account deleted successfully. {entry_count} entries and {folder_count} folders were removed.',
        'redirect': url_for('login')
    }

if __name__ == '__main__':
    app.run(debug=False, port=5001)