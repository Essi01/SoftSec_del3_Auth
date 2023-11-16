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


@app.errorhandler(429)
def ratelimit_handler(e):
    ip_address = get_remote_address()
    ban_duration = timedelta(minutes=30)  # Set the desired ban duration
    BANNED_IPS[ip_address] = datetime.now() + ban_duration
    return make_response(render_template('429.html'), 429)




# Global dictionary to track failed login attempts by IP address
failed_logins_by_ip = {}  # Format: {'ip_address': (last_attempt_time, count)}


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Adjust the rate limit as needed
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

        if user and bcrypt.checkpw(password, user['password']):
            # Check TOTP token
            totp_token = request.form['totp_token']
            totp_secret = get_totp_secret_for_user(username)

            if totp_secret:
                totp = pyotp.TOTP(totp_secret)
                if totp.verify(totp_token):
                    # Reset failed login counters upon successful login
                    session.pop(failed_login_key, None)
                    session.pop(totp_failed_key, None)
                    failed_logins_by_ip[ip_address] = (current_time, 0)
                    session['user_id'] = user['id']
                    flash('Logged in successfully!')
                    return redirect(url_for('index'))
                else:
                    # TOTP failed, increment counter
                    failed_attempts_totp = session.get(totp_failed_key, 0) + 1
                    session[totp_failed_key] = failed_attempts_totp
                    if failed_attempts_totp >= 3:
                        session[lockout_key] = current_time + timedelta(minutes=5)
                        flash('Account locked for 5 minutes due to failed TOTP attempts.')
                        return render_template('login.html')
                    flash('Invalid TOTP token')
            else:
                flash('Invalid username, password, or Two-Factor Token')

            # Increment failed login counters
            failed_attempts_user = session.get(failed_login_key, 0) + 1
            session[failed_login_key] = failed_attempts_user
            _, failed_attempts_ip = failed_logins_by_ip.get(ip_address, (current_time, 0))
            failed_logins_by_ip[ip_address] = (current_time, failed_attempts_ip + 1)

            # User-specific lockout after 3 failed attempts
            if failed_attempts_user >= 3:
                lockout_duration = timedelta(minutes=5)  # Lockout duration
                session[lockout_key] = current_time + lockout_duration
                flash(f'Account locked for {lockout_duration.seconds // 60} minutes due to failed attempts.')

        return render_template('login.html')

    return render_template('login.html')


def inform_lockout(lockout_time):
    lockout_remaining = int((lockout_time - datetime.now()).total_seconds())
    flash(f'Account locked for {lockout_remaining} seconds.')
    return render_template('login.html')

def update_lockout_counter(lockout_key):
    failed_attempts = session.get(lockout_key, 0) + 1
    if failed_attempts >= 3:
        return datetime.now() + timedelta(minutes=5)
    session[lockout_key] = failed_attempts
    return None

def validate_totp(totp_token, totp_secret):
    totp = pyotp.TOTP(totp_secret)
    return totp.verify(totp_token)



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
            return redirect(url_for('show_qr_code'))  # Updated line
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
    img = qrcode.make(totp_uri)
    img_stream = io.BytesIO()
    img.save(img_stream, format='PNG')
    img_stream.seek(0)
    qr_code_data = base64.b64encode(img_stream.getvalue()).decode()

    return render_template('qr_code.html', qr_code_data=qr_code_data)



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

@app.route('/')
def index():
    conn = get_db_connection()
    posts = conn.execute('SELECT * FROM posts ORDER BY id DESC').fetchall()
    conn.close()
    response = requests.get(API_ENDPOINT)
    articles = response.json().get('articles', [])[:4]
    return render_template('index.html', posts=posts, articles=articles)

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




@app.route('/submit', methods=['GET', 'POST'])
def submit():
    if 'user_id' not in session:
        # If not logged in, redirect to login page
        flash('You must be logged in to submit a post.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        author_id = session['user_id']
        tags = request.form.get('tags', '')
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        image_filename = None

        # Retrieve the username of the logged-in user
        conn = get_db_connection()
        user = conn.execute('SELECT username FROM users WHERE id = ?', (author_id,)).fetchone()
        conn.close()
        if user is None:
            flash('User not found.')
            return redirect(url_for('submit'))

        username = user['username']  # Username of the logged-in user

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

@app.errorhandler(429)
def too_many_requests(e):
    return render_template('429.html'), 429



if __name__ == '__main__':
    app.run(debug=True)
