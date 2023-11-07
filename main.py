from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
# from redis import Redis  # Uncomment if Redis is used
import sqlite3
import requests
from datetime import datetime, timedelta
import pytz
import os
from werkzeug.utils import secure_filename
from PIL import Image
import bcrypt

#T

# Set timezone for Oslo, Norway
local_tz = pytz.timezone('Europe/Oslo')

# Function to get the current time in local timezone
def get_current_time():
    return datetime.now(local_tz)

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Initialize Redis if used
# redis = Redis()

# Initialize Flask-Limiter with Redis storage if used
# limiter = Limiter(
#     key_func=get_remote_address,
#     storage_uri="redis://localhost:6379",
#     default_limits=["5 per minute", "1 per second"]
# )
# limiter.init_app(app)

DATABASE = 'blog.db'
API_KEY = 'your_api_key_here'
API_ENDPOINT = f'https://newsapi.org/v2/top-headlines?country=us&category=technology&apiKey={API_KEY}'

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Database connection
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Check if file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Initialize the database
def init_db():
    with app.app_context():
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                author TEXT,
                tags TEXT,
                timestamp TEXT,
                image_filename TEXT
            );
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            );
        ''')
        db.commit()
        db.close()

init_db()

# Initialize Flask-Limiter without the app object
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["5 per minute", "1 per second"],
)
limiter.init_app(app)

# Global variable to track the total number of failed login attempts
global_failed_logins = 0

@app.route('/login', methods=['GET', 'POST'])
def login():
    # No need for a global variable if you're tracking per account

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        # Try to get the lockout timestamp from the session
        lockout_key = f'lockout_{username}'
        lockout_time = session.get(lockout_key)

        # Check if the user is currently locked out
        if lockout_time and datetime.now(local_tz) < lockout_time:
            lockout_remaining = int((lockout_time - datetime.now(local_tz)).total_seconds())
            flash(f'The account is locked for {lockout_remaining} seconds. Try again later.')
            return render_template('login.html')

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and bcrypt.checkpw(password, user['password']):
            # Clear lockout and failed attempts
            session.pop(lockout_key, None)
            flash('You were successfully logged in')
            session['user_id'] = user['id']
            return redirect(url_for('index'))
        else:
            # Track the number of failed login attempts in the session
            session['failed_logins'] = session.get('failed_logins', 0) + 1

            # If there are three failed attempts, lock the account for 5 minutes
            if session['failed_logins'] >= 3:
                lockout_duration = timedelta(minutes=5)
                lockout_time = datetime.now(local_tz) + lockout_duration
                session[lockout_key] = lockout_time
                session.pop('failed_logins', None)  # Reset failed login counter after lockout
                flash(f'The account is locked for 5 minutes. Try again later.')
            else:
                flash('Invalid username or password')

            return render_template('login.html')

    # Clear failed logins count on GET request to login page
    session.pop('failed_logins', None)
    return render_template('login.html')



@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You were logged out')
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("2 per minute")  # Rate limit for registration attempts
def register():
    if request.method == 'POST':
        username = request.form['username']
        # You should encode the password here before hashing
        password = request.form['password'].encode('utf-8')

        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

        try:
            conn = get_db_connection()
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
        except sqlite3.IntegrityError:
            flash('Username already taken')
            return redirect(url_for('register'))
        except sqlite3.DatabaseError as e:
            flash('Database error: ' + str(e))
            return redirect(url_for('register'))
        finally:
            if conn:
                conn.close()
        flash('You were successfully registered and can now login')
        return redirect(url_for('login'))
    return render_template('register.html')

def init_db():
    with app.app_context():
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                author TEXT,
                tags TEXT,
                timestamp TEXT,
                image_filename TEXT
            );
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            );
        ''')
        db.commit()
        db.close()

init_db()

@app.route('/')
def index():
    conn = get_db_connection()
    posts = conn.execute('SELECT * FROM posts ORDER BY id DESC').fetchall()
    conn.close()
    response = requests.get(API_ENDPOINT)
    articles = response.json().get('articles', [])[:4]
    return render_template('index.html', posts=posts, articles=articles)

@app.route('/submit', methods=['GET', 'POST'])
def submit():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        author = session['user_id']
        tags = request.form.get('tags', '')
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        image_filename = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                with Image.open(file_path) as img:
                    img = img.resize((300, 200), Image.ANTIALIAS)
                    img.save(file_path)
                image_filename = filename
        if not title or not content:
            flash('Title and Content are required!')
            return redirect(url_for('submit'))
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO posts (title, content, author, tags, timestamp, image_filename)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (title, content, author, tags, current_time, image_filename))
        conn.commit()
        conn.close()
        flash('Your post has been created!')
        return redirect(url_for('index'))
    return render_template('submit.html')

@app.errorhandler(429)
def too_many_requests(e):
    return render_template('429.html'), 429



if __name__ == '__main__':
    app.run(debug=True)
