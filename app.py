from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
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

@app.route('/option_chain', methods=['GET', 'POST'])
@login_required
def option_chain():
    access_token = get_user_token()
    option_data = []
    spot_price = None
    available_expiries = []
    selected_expiry = None
    pcr = None
    atm_strike = None
    
    # Add index selection
    selected_index = request.form.get('index', 'nifty')  # Default to Nifty
    
    if access_token:
        try:
            # Define index keys based on selection
            if selected_index == 'sensex':
                index_key = 'BSE_INDEX|SENSEX'
                index_display_name = 'Sensex'
            else:  # Default to Nifty
                index_key = 'NSE_INDEX|Nifty 50'
                index_display_name = 'Nifty 50'
            
            # Get spot price first
            spot_url = f'https://api.upstox.com/v2/market-quote/ltp?instrument_key={index_key}'
            headers = {
                'Accept': 'application/json',
                'Authorization': f'Bearer {access_token}'
            }
            
            spot_response = requests.get(spot_url, headers=headers)
            print(f"Spot price response: {spot_response.status_code}")
            
            if spot_response.status_code == 200:
                spot_data = spot_response.json().get('data', {})
                # Handle different response formats
                formatted_key = index_key.replace('|', ':')
                index_data = spot_data.get(formatted_key, {}) or spot_data.get(index_key, {})
                if index_data:
                    spot_price = index_data.get('last_price')
                    print(f"Spot price: {spot_price}")
            
            # Get all available expiry dates using the market instruments API
            # The old endpoint is returning 404, let's use a different approach
            print("Fetching available expiry dates...")
            
            # Instead of using the derivatives endpoint, let's use the option chain API directly
            # with a default expiry date and then extract available expiries from the response
            
            # For Nifty options
            if selected_index == 'nifty':
                search_term = 'NIFTY'
                # Use a hardcoded list of common expiry dates for the current month and next month
                from datetime import datetime, timedelta
                
                current_date = datetime.now()
                
                # Get all Thursdays for the next 3 months
                available_expiries = []
                start_date = current_date
                end_date = current_date + timedelta(days=90)  # Look ahead 90 days
                
                # Add weekly expiries (all Thursdays)
                test_date = start_date
                while test_date <= end_date:
                    # If it's a Thursday
                    if test_date.weekday() == 3:
                        # Format as YYYY-MM-DD
                        formatted_expiry = test_date.strftime('%Y-%m-%d')
                        available_expiries.append(formatted_expiry)
                        test_date += timedelta(days=1)  # Move to next day
                    else:
                        test_date += timedelta(days=1)  # Move to next day
                
                print(f"Generated expiry dates: {available_expiries}")
            else:
                # For Sensex, use the same approach as Nifty
                search_term = 'SENSEX'
                from datetime import datetime, timedelta
                
                current_date = datetime.now()
                
                # Get all Thursdays for the next 3 months
                available_expiries = []
                start_date = current_date
                end_date = current_date + timedelta(days=90)  # Look ahead 90 days
                
                # Add weekly expiries (all Thursdays)
                test_date = start_date
                while test_date <= end_date:
                    # If it's a Thursday
                    if test_date.weekday() == 3:
                        # Format as YYYY-MM-DD
                        formatted_expiry = test_date.strftime('%Y-%m-%d')
                        available_expiries.append(formatted_expiry)
                        test_date += timedelta(days=1)  # Move to next day
                    else:
                        test_date += timedelta(days=1)  # Move to next day
                
                print(f"Generated expiry dates: {available_expiries}")
            
            # Check if we have any expiry dates
            if not available_expiries:
                print("No expiry dates generated")
                flash("No option expiry dates available. Please try again later.")
                return render_template('option_chain.html', 
                                    username=current_user.username,
                                    access_token=access_token,
                                    option_data=[],
                                    spot_price=spot_price,
                                    available_expiries=[],
                                    selected_expiry=None,
                                    pcr=None,
                                    atm_strike=None,
                                    selected_index=selected_index,
                                    index_display_name=index_display_name)
            
            # Get selected expiry from form or use first available
            if request.method == 'POST':
                if request.form.get('manual_expiry'):
                    # Use manually entered date if provided
                    selected_expiry = request.form.get('manual_expiry')
                    # Add to available expiries if not already there
                    if selected_expiry not in available_expiries:
                        available_expiries.append(selected_expiry)
                        # Sort the expiries to maintain chronological order
                        available_expiries.sort()
                elif request.form.get('expiry'):
                    selected_expiry = request.form.get('expiry')
            elif available_expiries:
                selected_expiry = available_expiries[0]
            
            print(f"Selected expiry: {selected_expiry}")
            
            # If we have a selected expiry, get option chain for that expiry
            if selected_expiry:
                # Use the option chain API endpoint
                chain_url = 'https://api.upstox.com/v2/option/chain'
                chain_params = {
                    'instrument_key': index_key,
                    'expiry_date': selected_expiry
                }
                
                chain_response = requests.get(chain_url, headers=headers, params=chain_params)
                print(f"Option Chain Response: {chain_response.status_code}")
                print(f"Request URL: {chain_url}")
                print(f"Request params: {chain_params}")
                
                if chain_response.status_code == 200:
                    chain_data = chain_response.json().get('data', [])
                    print(f"Chain data length: {len(chain_data)}")
                    
                    # Save the response to a file for debugging
                    with open('d:/algoproject/chain_response.json', 'w') as f:
                        import json
                        json.dump(chain_response.json(), f, indent=2)
                    
                    # Check if we have any data in the chain
                    if not chain_data:
                        print("No option chain data available for the selected criteria")
                        print(f"Full response: {chain_response.text}")
                        
                        # Try with a different date format (some APIs require YYYYMMDD)
                        if '-' in selected_expiry:
                            alt_date = selected_expiry.replace('-', '')
                            print(f"Trying alternative date format: {alt_date}")
                            
                            alt_chain_params = {
                                'instrument_key': index_key,
                                'expiry_date': alt_date
                            }
                            
                            alt_chain_response = requests.get(chain_url, headers=headers, params=alt_chain_params)
                            print(f"Alternative format response: {alt_chain_response.status_code}")
                            
                            if alt_chain_response.status_code == 200:
                                alt_chain_data = alt_chain_response.json().get('data', [])
                                if alt_chain_data:
                                    print(f"Alternative format successful! Data length: {len(alt_chain_data)}")
                                    chain_data = alt_chain_data
                                else:
                                    print("Alternative format also returned no data")
                        
                        # If still no data, show error message
                        if not chain_data:
                            # Clear any existing flashed messages to prevent duplication
                            session.pop('_flashes', None)
                            flash("No option chain data available for the selected criteria. "
                                "This could be due to:<br>"
                                "• The selected expiry date may not have options available<br>"
                                "• The API may be experiencing issues<br>"
                                "• The market may be closed<br>"
                                "• Your Upstox connection may need to be refreshed", 'error')
                            return render_template('option_chain.html', 
                                                username=current_user.username,
                                                access_token=access_token,
                                                option_data=[],
                                                spot_price=spot_price,
                                                available_expiries=available_expiries,
                                                selected_expiry=selected_expiry,
                                                pcr=None,
                                                atm_strike=None,
                                                selected_index=selected_index,
                                                index_display_name=index_display_name)
                    
                    # Process the option chain data
                    processed_data = []
                    
                    for option in chain_data:
                        # Extract data from the API response
                        strike_price = option.get('strike_price', 0)
                        
                        # Get call option data
                        call_options = option.get('call_options', {})
                        call_market_data = call_options.get('market_data', {}) if call_options else {}
                        call_greeks = call_options.get('option_greeks', {}) if call_options else {}
                        
                        # Get put option data
                        put_options = option.get('put_options', {})
                        put_market_data = put_options.get('market_data', {}) if put_options else {}
                        put_greeks = put_options.get('option_greeks', {}) if put_options else {}
                        
                        # Create a structured option data object
                        # In your option chain route, update the option_item dictionary creation:
                        
                        option_item = {
                            'strike_price': strike_price,
                            'call_oi': call_market_data.get('oi', 0),
                            'call_volume': call_market_data.get('volume', 0),
                            'call_ltp': call_market_data.get('ltp', 0),
                            'call_change': 0,  # Not directly available in the API
                            'call_iv': call_greeks.get('iv', 0),
                            'call_delta': call_greeks.get('delta', 0),
                            'call_gamma': call_greeks.get('gamma', 0),
                            'call_theta': call_greeks.get('theta', 0),
                            'call_vega': call_greeks.get('vega', 0),
                            'call_pop': call_greeks.get('pop', 0),  # Add POP (Probability of Profit)
                            'put_oi': put_market_data.get('oi', 0),
                            'put_volume': put_market_data.get('volume', 0),
                            'put_ltp': put_market_data.get('ltp', 0),
                            'put_change': 0,  # Not directly available in the API
                            'put_iv': put_greeks.get('iv', 0),
                            'put_delta': put_greeks.get('delta', 0),
                            'put_gamma': put_greeks.get('gamma', 0),
                            'put_theta': put_greeks.get('theta', 0),
                            'put_vega': put_greeks.get('vega', 0),
                            'put_pop': put_greeks.get('pop', 0)  # Add POP (Probability of Profit)
                        }
                        
                        processed_data.append(option_item)
                    
                    # Sort by strike price
                    option_data = sorted(processed_data, key=lambda x: x['strike_price'])
                    
                    # Find ATM strike (closest to spot price)
                    if spot_price and option_data:
                        strikes = [option['strike_price'] for option in option_data]
                        atm_index = min(range(len(strikes)), key=lambda i: abs(strikes[i] - spot_price))
                        atm_strike = strikes[atm_index]
                        
                        # Limit to 15 strikes above and below ATM (instead of 10)
                        atm_index = next((i for i, item in enumerate(option_data) if item['strike_price'] == atm_strike), 0)
                        start_index = max(0, atm_index - 15)
                        end_index = min(len(option_data), atm_index + 16)  # +16 to include the ATM strike
                        option_data = option_data[start_index:end_index]
                    
                    # Calculate PCR (Put-Call Ratio) based on total OI
                    if option_data:
                        total_call_oi = sum(option['call_oi'] for option in option_data)
                        total_put_oi = sum(option['put_oi'] for option in option_data)
                        pcr = total_put_oi / total_call_oi if total_call_oi > 0 else 0
                        pcr = round(pcr, 2)  # Round to 2 decimal places
                
                else:
                    print(f"API Error: Status {chain_response.status_code}, Response: {chain_response.text}")
                    flash('Error fetching option chain data')
                    
        except Exception as e:
            print(f"Error in option chain route: {str(e)}")
            flash('Error fetching option chain data')
    
    return render_template('option_chain.html', 
                         username=current_user.username,
                         access_token=access_token,
                         option_data=option_data,
                         spot_price=spot_price,
                         available_expiries=available_expiries,
                         selected_expiry=selected_expiry,
                         pcr=pcr,
                         atm_strike=atm_strike,
                         selected_index=selected_index,
                         index_display_name=index_display_name)

@app.route('/market')
@login_required
def market():
    access_token = get_user_token()
    market_data = {
        'nifty': None,
        'banknifty': None
    }
    
    if access_token:
        try:
            # Define instrument keys with correct format
            nifty_key = 'NSE_INDEX|Nifty 50'
            banknifty_key = 'NSE_INDEX|Nifty Bank'
            
            # URL encode the instrument keys
            from urllib.parse import quote
            encoded_keys = quote(f"{nifty_key},{banknifty_key}")
            
            url = f'https://api.upstox.com/v2/market-quote/ltp?instrument_key={encoded_keys}'
            headers = {
                'Accept': 'application/json',
                'Authorization': f'Bearer {access_token}'
            }
            
            response = requests.get(url, headers=headers)
            print("API Response:", response.text)  # Debug print
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                
                # Process NIFTY data - handle new response format
                nifty_data = data.get('NSE_INDEX:Nifty 50', {}) or data.get(nifty_key, {})
                if nifty_data:
                    market_data['nifty'] = {
                        'last_price': nifty_data.get('last_price', 'N/A'),
                        'change': 0,  # We don't have change data in the new format
                        'change_percentage': 0,  # We don't have change percentage in the new format
                        'high': 'N/A',
                        'low': 'N/A',
                        'open': 'N/A',
                        'close': 'N/A',
                        'volume': 'N/A'
                    }
                
                # Process BANKNIFTY data - handle new response format
                banknifty_data = data.get('NSE_INDEX:Nifty Bank', {}) or data.get(banknifty_key, {})
                if banknifty_data:
                    market_data['banknifty'] = {
                        'last_price': banknifty_data.get('last_price', 'N/A'),
                        'change': 0,
                        'change_percentage': 0,
                        'high': 'N/A',
                        'low': 'N/A',
                        'open': 'N/A',
                        'close': 'N/A'
                    }
            else:
                print(f"API Error: Status {response.status_code}, Response: {response.text}")
                flash('Error fetching market data')
                
        except Exception as e:
            print(f"Error in market route: {str(e)}")
            flash('Error fetching market data')
    
    # If it's an AJAX request, return JSON data
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify(market_data)
    
    # Otherwise render the template
    return render_template('market.html', 
                         username=current_user.username,
                         access_token=access_token,
                         market_data=market_data)

@app.route('/market/update')
@login_required
def market_update():
    access_token = get_user_token()
    market_data = {
        'nifty': None,
        'banknifty': None
    }
    
    if access_token:
        try:
            # Define instrument keys with correct format
            nifty_key = 'NSE_INDEX|Nifty 50'
            banknifty_key = 'NSE_INDEX|Nifty Bank'
            
            # URL encode the instrument keys
            from urllib.parse import quote
            encoded_keys = quote(f"{nifty_key},{banknifty_key}")
            
            url = f'https://api.upstox.com/v2/market-quote/ltp?instrument_key={encoded_keys}'
            headers = {
                'Accept': 'application/json',
                'Authorization': f'Bearer {access_token}'
            }
            
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                
                # Process NIFTY data - handle new response format
                nifty_data = data.get('NSE_INDEX:Nifty 50', {}) or data.get(nifty_key, {})
                if nifty_data:
                    market_data['nifty'] = {
                        'last_price': nifty_data.get('last_price', 'N/A'),
                        'change': 0,
                        'change_percentage': 0,
                        'high': 'N/A',
                        'low': 'N/A',
                        'open': 'N/A',
                        'close': 'N/A',
                        'volume': 'N/A'
                    }
                
                # Process BANKNIFTY data - handle new response format
                banknifty_data = data.get('NSE_INDEX:Nifty Bank', {}) or data.get(banknifty_key, {})
                if banknifty_data:
                    market_data['banknifty'] = {
                        'last_price': banknifty_data.get('last_price', 'N/A'),
                        'change': 0,
                        'change_percentage': 0,
                        'high': 'N/A',
                        'low': 'N/A',
                        'open': 'N/A',
                        'close': 'N/A'
                    }
            
            return jsonify(market_data)
                
        except Exception as e:
            print(f"Error in market update route: {str(e)}")
            return jsonify({'error': str(e)})
    
    return jsonify({'error': 'No access token'})

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
    # Initialize database if it doesn't exist
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
    else:
        # Check if columns exist and add them if they don't
        db = get_db()
        columns = db.execute("PRAGMA table_info(users)").fetchall()
        column_names = [column[1] for column in columns]
        
        if 'client_id' not in column_names:
            db.execute("ALTER TABLE users ADD COLUMN client_id TEXT")
        if 'client_secret' not in column_names:
            db.execute("ALTER TABLE users ADD COLUMN client_secret TEXT")
        if 'redirect_uri' not in column_names:
            db.execute("ALTER TABLE users ADD COLUMN redirect_uri TEXT")
        if 'access_token' not in column_names:
            db.execute("ALTER TABLE users ADD COLUMN access_token TEXT")
        
        db.commit()
        db.close()
        
    app.run(debug=True)


@app.route('/initiate_upstox_auth')
@login_required
def initiate_upstox_auth():
    try:
        db = get_db()
        # First check if the columns exist
        columns = db.execute("PRAGMA table_info(users)").fetchall()
        column_names = [column[1] for column in columns]
        
        # Check if required columns exist
        if not all(col in column_names for col in ['client_id', 'client_secret', 'redirect_uri']):
            # Add missing columns if they don't exist
            if 'client_id' not in column_names:
                db.execute("ALTER TABLE users ADD COLUMN client_id TEXT")
            if 'client_secret' not in column_names:
                db.execute("ALTER TABLE users ADD COLUMN client_secret TEXT")
            if 'redirect_uri' not in column_names:
                db.execute("ALTER TABLE users ADD COLUMN redirect_uri TEXT")
            db.commit()
            flash('Database schema updated. Please enter your Upstox API credentials.')
            return redirect(url_for('profile'))
        
        # Get user data
        user = db.execute("SELECT client_id, client_secret, redirect_uri FROM users WHERE id = ?", 
                         (current_user.id,)).fetchone()
        db.close()
        
        if not user or not user['client_id'] or not user['client_secret'] or not user['redirect_uri']:
            flash('Missing Upstox API credentials. Please update your connection details first.')
            return redirect(url_for('profile'))
            
        # Store in session for later use
        session['upstox_credentials'] = {
            'client_id': user['client_id'],
            'client_secret': user['client_secret'],
            'redirect_uri': user['redirect_uri']
        }
        
        # Generate authorization URL with proper URL encoding
        auth_params = {
            'response_type': 'code',
            'client_id': user['client_id'],
            'redirect_uri': user['redirect_uri']
        }
        
        # Print debug info
        print(f"Initiating Upstox auth with params: {auth_params}")
        
        # Use the same URL format as in connect_upstox function
        auth_url = f"https://api.upstox.com/v2/login/authorization/dialog?{urlencode(auth_params)}"
        print(f"Redirecting to: {auth_url}")
        
        # Redirect to Upstox authorization page
        return redirect(auth_url)
    except Exception as e:
        error_msg = f'Error initiating Upstox authentication: {str(e)}'
        print(error_msg)
        flash(error_msg)
        return redirect(url_for('profile'))