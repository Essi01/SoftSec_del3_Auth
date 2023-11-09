from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, make_response
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
import requests



# Mock constants for client ID and secret. Replace with actual values.
CLIENT_ID = "975322633742-6p76ijo20mcfughs1fbek534fc8mqi3b.apps.googleusercontent.com"
CLIENT_SECRET = "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"
REDIRECT_URI = "http://localhost:5000/callback" # This is one of the redirect URIs configured in Google Cloud Console
# API key form Google Cloud AIzaSyBHRUJnLzfn6cjpg5Qs-JpvCg1FZDEZGAU


# Set timezone for Oslo, Norway
local_tz = pytz.timezone('Europe/Oslo')

# Function to get the current time in local timezone
def get_current_time():
    return datetime.now(local_tz)

encryption_key = Fernet.generate_key()
fernet = Fernet(encryption_key)

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

def get_totp_secret_for_user(username):
    # Get database connection
    conn = get_db_connection()
    try:
        # Retrieve the encrypted user's TOTP secret from the database
        encrypted_totp_secret = conn.execute('SELECT totp_secret FROM users WHERE username = ?', (username,)).fetchone()
        if encrypted_totp_secret:
            # Decrypt the TOTP secret before using it
            totp_secret = fernet.decrypt(encrypted_totp_secret['totp_secret']).decode()
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
        # Ensure the users table exists with the required columns
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                totp_secret TEXT NOT NULL UNIQUE
            );
        ''')
        # Add any other table creation logic here
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

@app.before_request
def check_ban_status():
    ip_address = get_remote_address()
    if ip_address in BANNED_IPS:
        if datetime.now() < BANNED_IPS[ip_address]:
            # Return the 429 response if the ban is still in place
            return make_response(render_template('429.html'), 429)
        else:
            # Remove the IP from the ban list if the ban time has passed
            del BANNED_IPS[ip_address]

@app.errorhandler(429)
def ratelimit_handler(e):
    ip_address = get_remote_address()
    ban_duration = timedelta(minutes=30)  # Set the desired ban duration
    BANNED_IPS[ip_address] = datetime.now() + ban_duration
    return make_response(render_template('429.html'), 429)


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
            # Retrieve TOTP token from the login form
            totp_token = request.form['totp_token']
            totp = pyotp.TOTP(user['totp_secret'])

            # Verify the TOTP token
            if totp.verify(totp_token):
                # TOTP is valid, proceed with login
                session['user_id'] = user['id']  # Assuming 'id' is the identifier in your 'users' table
                flash('Logged in successfully!')
                return redirect(url_for('index'))  # Redirect to a page that indicates a successful login
            else:
                flash('Invalid TOTP token')
                return render_template('login.html')

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



@app.route('/logout', methods=['POST'])
def logout():
    # Log the user out by removing 'user_id' from session
    session.pop('user_id', None)
    flash('You were logged out')
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("2 per minute")
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
        totp_secret = generate_totp_secret()

        # Create a TOTP object and generate a URI for QR code
        totp_uri = get_totp_uri(totp_secret, username)
        # Generate QR code
        img = qrcode.make(totp_uri)
        # Convert the QR code to an image file stream
        img_stream = io.BytesIO()
        img.save(img_stream)
        img_stream.seek(0)

        try:
            conn = get_db_connection()
            conn.execute('INSERT INTO users (username, password, totp_secret) VALUES (?, ?, ?)',
                         (username, hashed_password, totp_secret))
            conn.commit()
            # After successful registration, display the QR code for the user to scan
            session['username_for_qr'] = username  # Save the username in session to be used in the QR code route
            return redirect(url_for('show_qr_code'))
        except sqlite3.IntegrityError:
            flash('Username already taken')
            return redirect(url_for('register'))
        except sqlite3.DatabaseError as e:
            flash('Database error: ' + str(e))
            return redirect(url_for('register'))
        finally:
            if conn:
                conn.close()

    return render_template('register.html')


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

    # Generate the QR code
    img = qrcode.make(totp_uri)
    img_stream = io.BytesIO()
    img.save(img_stream, "PNG")
    img_stream.seek(0)
    data_url = base64.b64encode(img_stream.getvalue()).decode()
    img_data = f"data:image/png;base64,{data_url}"
    return render_template('qr_code.html', img_data=img_data)


# OAuth2 callback route for Google login flow (configured in Google Cloud Console) - GET request only (no POST) - no rate limiting applied here since it's a callback route and not directly accessible by the user (unless they try to access it directly)

# OAuth Endpoints
@app.route("/auth")
def auth():
    # Redirect the user to the OAuth provider for authorization
    # Construct the authorization URL with necessary parameters like client_id and redirect_uri
    authorization_url = f"https://oauth_provider.com/auth?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&scope=scope"
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    # Get the authorization code from the callback URL
    code = request.args.get('code')

    # Exchange the authorization code for an access token
    token_response = requests.post(
        "https://oauth_provider.com/token",
        data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
            "code": code,
            "grant_type": "authorization_code"
        }
    )

    # Extract the access token from the response
    access_token = token_response.json().get('access_token')

    # Save the access token in the user session or database
    session['access_token'] = access_token

    # Redirect to a protected resource or home page
    return redirect(url_for('index'))

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
        # If not logged in, redirect to login page
        flash('You must be logged in to submit a post.')
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        # Since we checked if the user is logged in, we can safely get the user_id from the session
        author_id = session['user_id']
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
