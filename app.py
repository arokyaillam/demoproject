from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from urllib.parse import urlencode

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # type: ignore

class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

def get_db():
    db = sqlite3.connect('database.db')
    db.row_factory = sqlite3.Row
    return db

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    db.close()
    if user:
        return User(user['id'], user['username'], user['password'])
    return None

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        try:
            user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            
            if user and check_password_hash(user['password'], password):
                user_obj = User(user['id'], user['username'], user['password'])
                login_user(user_obj)
                
                # Store access token in a variable before closing db
                access_token = user['access_token'] if 'access_token' in user.keys() else None
                db.close()
                
                # Check Upstox connection
                if not access_token:
                    flash('Please connect your Upstox account to access all features')
                    return redirect(url_for('profile'))
                
                # Verify if token is still valid
                try:
                    headers = {
                        'Accept': 'application/json',
                        'Authorization': f'Bearer {access_token}'
                    }
                    response = requests.get('https://api.upstox.com/v2/user/profile', headers=headers)
                    if response.status_code != 200:
                        flash('Your Upstox connection needs to be renewed')
                        return redirect(url_for('profile'))
                except Exception:
                    flash('Unable to verify Upstox connection')
                    return redirect(url_for('profile'))
                    
                return redirect(url_for('dashboard'))
            
            flash('Invalid username or password')
            db.close()
        except Exception as e:
            db.close()
            flash(f'Login error: {str(e)}')
            
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        if db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
            flash('Username already exists')
        else:
            hashed_password = generate_password_hash(password)
            db.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                      (username, hashed_password))
            db.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        db.close()
    return render_template('signup.html')

def get_user_token():
    db = get_db()
    user = db.execute('SELECT access_token FROM users WHERE id = ?', (current_user.id,)).fetchone()
    db.close()
    return user['access_token'] if user and 'access_token' in user.keys() else None

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', 
                         username=current_user.username,
                         access_token=get_user_token())

# Update other route functions similarly
@app.route('/strategy')
@login_required
def strategy():
    return render_template('strategy.html', 
                         username=current_user.username,
                         access_token=get_user_token())

@app.route('/testing')
@login_required
def testing():
    return render_template('testing.html', 
                         username=current_user.username,
                         access_token=get_user_token())

@app.route('/orders')
@login_required
def orders():
    return render_template('orders.html', 
                         username=current_user.username,
                         access_token=get_user_token())

@app.route('/option_chain')
@login_required
def option_chain():
    return render_template('option_chain.html', 
                         username=current_user.username,
                         access_token=get_user_token())

@app.route('/market')
@login_required
def market():
    return render_template('market.html', 
                         username=current_user.username,
                         access_token=get_user_token())

@app.route('/funds')
@login_required
def funds():
    access_token = get_user_token()
    fund_data = {
        'SEC': None,
        'COM': None
    }
    
    if access_token:
        # Fetch equity (SEC) segment funds
        try:
            url_sec = 'https://api.upstox.com/v2/user/get-funds-and-margin?segment=SEC'
            headers = {
                'Accept': 'application/json',
                'Authorization': f'Bearer {access_token}'
            }
            response_sec = requests.get(url_sec, headers=headers)
            if response_sec.status_code == 200:
                fund_data['SEC'] = response_sec.json().get('data', {})
        except Exception as e:
            flash(f'Error fetching equity funds: {str(e)}')
            print(f"API Error (SEC): {str(e)}")
        
        # Fetch commodity (COM) segment funds
        try:
            url_com = 'https://api.upstox.com/v2/user/get-funds-and-margin?segment=COM'
            headers = {
                'Accept': 'application/json',
                'Authorization': f'Bearer {access_token}'
            }
            response_com = requests.get(url_com, headers=headers)
            if response_com.status_code == 200:
                fund_data['COM'] = response_com.json().get('data', {})
        except Exception as e:
            flash(f'Error fetching commodity funds: {str(e)}')
            print(f"API Error (COM): {str(e)}")
    
    return render_template('funds.html', 
                         username=current_user.username,
                         access_token=access_token,
                         fund_data=fund_data)

@app.route('/alert-settings')
@login_required
def alert_settings():
    return render_template('alert_settings.html', 
                         username=current_user.username,
                         access_token=get_user_token())

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/connect_upstox', methods=['POST'])
@login_required
def connect_upstox():
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    redirect_uri = request.form.get('redirect_uri')
    
    if not all([client_id, client_secret, redirect_uri]):
        flash('All fields are required')
        return redirect(url_for('profile'))
    
    # Store API credentials in session
    session['upstox_credentials'] = {
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri
    }
    
    # Generate authorization URL
    auth_params = {
        'response_type': 'code',
        'client_id': client_id,
        'redirect_uri': redirect_uri
    }
    auth_url = f"https://api.upstox.com/v2/login/authorization/dialog?{urlencode(auth_params)}"
    return redirect(auth_url)

@app.route('/callback')  # Changed from '/upstox/callback' to '/callback'
@login_required
def upstox_callback():
    code = request.args.get('code')
    credentials = session.get('upstox_credentials')
    
    if not code or not credentials:
        flash('Authorization failed')
        return redirect(url_for('dashboard'))
    
    url = 'https://api.upstox.com/v2/login/authorization/token'
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    
    data = {
        'code': code,
        'client_id': credentials['client_id'],
        'client_secret': credentials['client_secret'],
        'redirect_uri': credentials['redirect_uri'],
        'grant_type': 'authorization_code',
    }
    
    try:
        response = requests.post(url, headers=headers, data=data)
        if response.status_code == 200:
            token_data = response.json()
            db = get_db()
            db.execute('''
                UPDATE users 
                SET access_token = ?, client_id = ?, client_secret = ?, redirect_uri = ?
                WHERE id = ?
            ''', (
                token_data.get('access_token'),
                credentials['client_id'],
                credentials['client_secret'],
                credentials['redirect_uri'],
                current_user.id
            ))
            db.commit()
            db.close()
            flash('Successfully connected to Upstox!')
        else:
            flash('Failed to connect to Upstox')
    except Exception as e:
        flash(f'Error: {str(e)}')
    
    return redirect(url_for('dashboard'))

@app.route('/profile')
@login_required
def profile():
    try:
        db = get_db()
        # First check if the columns exist
        columns = db.execute("PRAGMA table_info(users)").fetchall()
        column_names = [column[1] for column in columns]
        
        # Build query based on existing columns
        select_columns = ['access_token']
        if 'client_id' in column_names:
            select_columns.extend(['client_id', 'client_secret', 'redirect_uri'])
        
        query = f"SELECT {', '.join(select_columns)} FROM users WHERE id = ?"
        user = db.execute(query, (current_user.id,)).fetchone()
        db.close()

        profile_data = None
        if user and user['access_token']:
            try:
                url = 'https://api.upstox.com/v2/user/profile'
                headers = {
                    'Accept': 'application/json',
                    'Authorization': f'Bearer {user["access_token"]}'
                }
                response = requests.get(url, headers=headers)
                print("API Response:", response.text)  # Debug print
                
                if response.status_code == 200:
                    data = response.json().get('data', {})
                    profile_data = data
                else:
                    flash(f'Failed to fetch profile data: {response.text}')
            except Exception as e:
                flash(f'Error fetching profile: {str(e)}')
                print(f"API Error: {str(e)}")  # Debug print

        return render_template('profile.html', 
                             username=current_user.username,
                             profile_data=profile_data,
                             connection_details=user if user else None)
                             
    except Exception as e:
        flash(f'Database error: {str(e)}')
        print(f"Database Error: {str(e)}")  # Debug print
        return render_template('profile.html', 
                             username=current_user.username,
                             profile_data=None,
                             connection_details=None)



if __name__ == '__main__':
    # Keep this part
    if not os.path.exists('database.db'):
        db = get_db()
        db.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                access_token TEXT,
                client_id TEXT,
                client_secret TEXT,
                redirect_uri TEXT
            )
        ''')
        db.commit()
        db.close()
    app.run(debug=True)