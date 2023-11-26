from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
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
import pyotp
import io
import qrcode
from cryptography.fernet import Fernet
import base64
from oauthlib.oauth2 import WebApplicationClient
import json
import re
from flask import current_app


# OAuth2 Configuration redirect URI
REDIRECT_URI = "http://127.0.0.1:5000/callback"


# Set environment variables for testing with HTTP
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'   # DO NOT USE IN PRODUCTION


# Function to generate a Fernet key
def load_key():
    """Load the Fernet key from the file."""
    try:
        with open('fernet_key.txt', 'rb') as file:
            key = file.read()
        return key
    except FileNotFoundError:
        raise RuntimeError("Fernet key file not found. Please generate a key.")


# Load the Fernet key
encryption_key = load_key()
fernet = Fernet(encryption_key)


# Test encryption and decryption
def test_encryption():
    # Use a known secret for testing
    test_secret = pyotp.random_base32()
    print(f"Original Secret: {test_secret}")

    # Encrypt the secret
    encrypted_secret = fernet.encrypt(test_secret.encode())
    print(f"Encrypted Secret: {encrypted_secret}")

    # Decrypt the secret
    decrypted_secret = fernet.decrypt(encrypted_secret).decode()
    print(f"Decrypted Secret: {decrypted_secret}")

    # Check if the round-trip was successful
    assert test_secret == decrypted_secret, "The decrypted secret does not match the original"


# Set timezone for Oslo, Norway
local_tz = pytz.timezone('Europe/Oslo')


# Function to get the current time in local timezone
def get_current_time():
    return datetime.now(local_tz)


# Function to generate a TOTP secret
def generate_totp_secret():
    secret = pyotp.random_base32()
    # Encrypt the TOTP secret before storing it
    encrypted_secret = fernet.encrypt(secret.encode())
    return encrypted_secret


# Function to generate a TOTP URI
def get_totp_uri(secret, username):
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(username, issuer_name="TechSavvy")


# Function to get the TOTP secret for a user
def get_totp_secret_for_user(username):
    # Get database connection
    conn = get_db_connection()
    try:
        encrypted_totp_secret = conn.execute('SELECT totp_secret FROM users WHERE username = ?', (username,)).fetchone()
        if encrypted_totp_secret:
            # Check if the user's account is locked
            lockout_key = f'lockout_{username}'
            lockout_time = session.get(lockout_key)
            current_time = datetime.now(local_tz)
            if lockout_time and current_time < lockout_time:
                # Return None or some indication that the account is locked
                return None

            # Decrypt the TOTP secret if the account is not locked
            totp_secret = fernet.decrypt(encrypted_totp_secret['totp_secret'])
            return totp_secret
        else:
            return None
    except sqlite3.Error as e:
        print(f"An error occurred: {e.args[0]}")
        return None
    finally:
        # Close the database connection
        conn.close()


app = Flask(__name__)
app.secret_key = "supersecretkey"


# OAuth2 Configuration (Replace with your actual credentials)
GOOGLE_CLIENT_ID = "975322633742-6p76ijo20mcfughs1fbek534fc8mqi3b.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# Create OAuth2 client
oauth2_client = WebApplicationClient(GOOGLE_CLIENT_ID)

AUTH_CODES = {}
TOKENS = {}

# Database configuration and initialization
DATABASE = 'blog.db'
API_KEY = '545b4cb9483a4dee8f562ae8300d2224'
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
                password TEXT NOT NULL,
                client_id TEXT,
                client_secret TEXT,
                totp_secret TEXTE
            );
        ''')
        db.commit()
        db.close()


# Call the init_db function to update the database
init_db()


# Initialize Flask-Limiter without the app object
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["5 per minute", "1 per second"],
)
limiter.init_app(app)


# Create a dictionary to track banned IPs
BANNED_IPS = {}


# Register a function to run before each request
@app.before_request
def check_ban_status():
    ip_address = get_remote_address()

    # Check if the IP is in the banned IPs list
    if ip_address in BANNED_IPS:
        ban_end_time = BANNED_IPS[ip_address]
        current_time = datetime.now()

        # Check if the ban is still active
        if current_time < ban_end_time:
            return make_response(render_template('429.html'), 429)
        else:
            # Remove the IP from the ban list if the ban time has passed
            del BANNED_IPS[ip_address]


# Check if the IP is in the failed login attempts list
@app.errorhandler(429)
def ratelimit_handler():
    ip_address = get_remote_address()
    ban_duration = timedelta(minutes=30)  # Set the desired ban duration
    BANNED_IPS[ip_address] = datetime.now() + ban_duration
    return make_response(render_template('429.html'), 429)


# Global dictionary to track failed login attempts by IP address
failed_logins_by_ip = {}  # Format: {'ip_address': (last_attempt_time, count)}

# Global dictionary to track user lockouts
user_lockouts = {}


# Login route
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    ip_address = get_remote_address()
    current_time = datetime.now(local_tz)

    # Reset the IP-based counter if more than 10 minutes have passed
    if ip_address in failed_logins_by_ip:
        last_attempt_time, _ = failed_logins_by_ip[ip_address]
        if current_time - last_attempt_time > timedelta(minutes=10):
            failed_logins_by_ip[ip_address] = (current_time, 0)

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        # User-specific keys for failed login attempts and lockout
        failed_login_key = f'failed_{username}'
        totp_failed_key = f'totp_failed_{username}'
        lockout_key = f'lockout_{username}'
        lockout_time = session.get(lockout_key)

        # Check for account lockout
        if lockout_time and current_time < lockout_time:
            lockout_remaining = int((lockout_time - current_time).total_seconds())
            flash(f'Account locked for {lockout_remaining} seconds.')
            return render_template('login.html')

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        valid_login = False

        if user and bcrypt.checkpw(password, user['password']):
            # Check TOTP token
            totp_token = request.form['totp_token']
            totp_secret = get_totp_secret_for_user(username)

            if totp_secret and validate_totp(totp_token, totp_secret):
                valid_login = True

        if valid_login:
            # Reset failed login counters upon successful login
            session.pop(failed_login_key, None)
            session.pop(totp_failed_key, None)
            failed_logins_by_ip[ip_address] = (current_time, 0)
            session['user_id'] = user['id']
            flash('Logged in successfully!')
            return redirect(url_for('index'))
        else:
            flash('Invalid username, password, or Two-Factor Token')

            # Update failed login counters
            update_failed_login_counters(username, ip_address, failed_login_key, totp_failed_key, lockout_key)

    return render_template('login.html', CLIENT_ID=GOOGLE_CLIENT_ID, REDIRECT_URI=REDIRECT_URI)


# Function to update failed login counters
def update_failed_login_counters(username, ip_address, failed_login_key, totp_failed_key, lockout_key):
    current_time = datetime.now(local_tz)

    # Update failed password attempts
    failed_attempts_user = session.get(failed_login_key, 0) + 1
    session[failed_login_key] = failed_attempts_user

    # Update failed TOTP attempts
    failed_attempts_totp = session.get(totp_failed_key, 0) + 1
    session[totp_failed_key] = failed_attempts_totp

    # Update failed login attempts by IP
    _, failed_attempts_ip = failed_logins_by_ip.get(ip_address, (current_time, 0))
    failed_logins_by_ip[ip_address] = (current_time, failed_attempts_ip + 1)

    # Apply lockout after 3 failed attempts (either password or TOTP)
    if failed_attempts_user >= 3 or failed_attempts_totp >= 3:
        lockout_duration = timedelta(minutes=5)  # Lockout duration
        session[lockout_key] = current_time + lockout_duration

        # Record the lockout in the user_lockouts dictionary

        # Optionally, record the lockout in another structure keyed by username
        # This can be useful for tracking lockouts across different sessions or IP addresses
        user_lockouts[username] = current_time + lockout_duration


# Function to validate a TOTP token
def validate_totp(totp_token, totp_secret):
    totp = pyotp.TOTP(totp_secret)
    return totp.verify(totp_token)


# Function to get the TOTP secret for a user
def inform_lockout(lockout_time):
    lockout_remaining = int((lockout_time - datetime.now()).total_seconds())
    flash(f'Account locked for {lockout_remaining} seconds.')
    return render_template('login.html')


# Function to get the TOTP secret for a user
def update_lockout_counter(lockout_key):
    failed_attempts = session.get(lockout_key, 0) + 1
    if failed_attempts >= 3:
        return datetime.now() + timedelta(minutes=5)
    session[lockout_key] = failed_attempts
    return None


# Function to get the TOTP secret for a user
def validate_totp(totp_token, totp_secret):
    totp = pyotp.TOTP(totp_secret)
    return totp.verify(totp_token)


# Logout route
@app.route('/logout', methods=['POST'])
def logout():
    # Clear the entire session
    session.clear()
    flash('You were logged out')
    return redirect(url_for('index'))


# Register route
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("4 per minute")
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # password validation
        if (len(password) < 8 or
                not re.search("[0-9]", password) or
                not re.search("[!@#$%^&*]", password) or
                not re.search("[a-z]", password) or
                not re.search("[A-Z]", password)):
            flash(
                'Password must be at least 8 characters long, include a number, a special character,'
                ' an uppercase letter, and a lowercase letter.')
            return redirect(url_for('register'))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        totp_secret = generate_totp_secret()

        # Create a TOTP object and generate a URI for QR code
        totp_uri = get_totp_uri(totp_secret, username)
        # Generate QR code
        img = qrcode.make(totp_uri)
        # Convert the QR code to an image file stream
        img_stream = io.BytesIO()
        img.save(img_stream)
        img_stream.seek(0)

        conn = None  # Initialize conn to None
        try:
            conn = get_db_connection()

            # Check if username already exists
            existing_user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
            if existing_user:
                flash('Username already taken, please choose another one.')
                return redirect(url_for('register'))

            # Proceed with registration since username is unique
            conn.execute('INSERT INTO users (username, password, totp_secret) VALUES (?, ?, ?)',
                         (username, hashed_password, totp_secret))
            conn.commit()

            # After successful registration, display the QR code for the user to scan
            session['username_for_qr'] = username  # Save the username in session to be used in the QR code route
            return redirect(url_for('show_qr_code'))  # Updated line

        except sqlite3.DatabaseError as e:
            flash('Database error: ' + str(e))
            return redirect(url_for('register'))
        finally:
            if conn:
                conn.close()
    return render_template('register.html')


# Route to display the QR code
@app.route('/show-qr-code')
def show_qr_code():
    username = session.pop('username_for_qr', None)
    if not username:
        flash('No username found for QR code generation.')
        return redirect(url_for('register'))

    totp_secret = get_totp_secret_for_user(username)
    if totp_secret is None:
        flash('Failed to retrieve TOTP secret for user.')
        return redirect(url_for('register'))

    totp_uri = get_totp_uri(totp_secret, username)
    img = qrcode.make(totp_uri)
    img_stream = io.BytesIO()
    img.save(img_stream, format='PNG')
    img_stream.seek(0)
    qr_code_data = base64.b64encode(img_stream.getvalue()).decode()

    return render_template('qr_code.html', qr_code_data=qr_code_data)


# Protected resource route for testing the OAuth2 flow with Google (not used in the blog)
@app.route("/protected_resource")
def protected_resource():
    # Use the access token to access a protected resource
    access_token = session.get('access_token')
    if not access_token:
        return "Access Denied", 403

    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    # Make a request to the protected resource
    response = requests.get('https://oauth_provider.com/resource', headers=headers)
    return response.content


# The main route of the application
@app.route('/')
def index():
    conn = get_db_connection()
    posts = conn.execute('SELECT * FROM posts ORDER BY id DESC').fetchall()
    conn.close()
    response = requests.get(API_ENDPOINT)
    articles = response.json().get('articles', [])[:4]
    return render_template('index.html', posts=posts, articles=articles)


# Post route to create a new post in the database
@app.route('/submit', methods=['GET', 'POST'])
def submit():
    # Check if logged in with local auth or Google OAuth
    if 'user_id' not in session and 'logged_in_with_google' not in session:
        flash('You must be logged in to submit a post.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        tags = request.form.get('tags', '')
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        image_filename = None

        # Determine the username
        if 'user_id' in session:
            # Get username from database for local authenticated users
            conn = get_db_connection()
            user = conn.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],)).fetchone()
            conn.close()
            if user is None:
                flash('User not found.')
                return redirect(url_for('submit'))
            username = user['username']
        else:
            # Assign a default username for Google-authenticated users
            username = "Google_User"

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
          ''', (title, content, username, tags, current_time, image_filename))
        conn.commit()
        conn.close()
        flash('Your post has been created!')
        return redirect(url_for('index'))
    return render_template('submit.html')


# Route to display a single post
@app.route('/show_templates')
def show_templates():
    return str(current_app.jinja_loader.list_templates())


# OAuth functions for the OAuth2
# Login route for the OAuth2 flow with Google
@app.route('/login_with_google')
def login_with_google():
    try:
        # Fetch the Google provider configuration
        google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
        authorization_endpoint = google_provider_cfg.get("authorization_endpoint")

        # Check if the authorization endpoint is correctly fetched
        if not authorization_endpoint:
            raise ValueError("Failed to fetch authorization endpoint from Google provider configuration.")

        # Debug print (remove in production)
        print(f"Authorization Endpoint: {authorization_endpoint}")

        # Construct the request for Google login
        request_uri = oauth2_client.prepare_request_uri(
            authorization_endpoint,
            redirect_uri=REDIRECT_URI,  # Use the constant defined at the beginning
            scope=["openid", "email", "profile"],
        )

        # Debug print (remove in production)
        print(f"Request URI: {request_uri}")

        # Redirect to the Google login page
        return redirect(request_uri)
    except Exception as e:
        # Log the exception (print for debugging, consider logging in production)
        print(f"An error occurred in login_with_google: {e}")

        # Handle the error appropriately (e.g., display an error message)
        flash("An error occurred while trying to authenticate with Google. Please try again later.")
        return redirect(url_for("index"))


# Callback route for the OAuth2 flow
@app.route('/callback')
def callback():
    code = request.args.get("code")
    if not code:
        flash("Authorization code not found", category="error")
        return redirect(url_for("login"))

    try:
        google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
        token_endpoint = google_provider_cfg["token_endpoint"]

        token_url, headers, body = oauth2_client.prepare_token_request(
            token_endpoint,
            authorization_response=request.url,
            redirect_url=REDIRECT_URI,
            code=code
        )
        token_response = requests.post(
            token_url,
            headers=headers,
            data=body,
            auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
        )

        tokens = token_response.json()
        oauth2_client.parse_request_body_response(json.dumps(tokens))

        session['logged_in_with_google'] = True
        session['access_token'] = tokens.get('access_token')
        flash('Logged in successfully with Google!', category="success")
        return redirect(url_for('index'))
    except Exception as e:
        flash(f"An error occurred: {e}", category="error")
        return redirect(url_for("login"))


# Error handlers
@app.errorhandler(429)
def too_many_requests():
    return render_template('429.html'), 429


# API routes for the blog
if __name__ == '__main__':
    app.run(debug=True)
