from flask import Flask, redirect, url_for, session, request, jsonify
from authlib.integrations.flask_client import OAuth
import os
import uuid
import requests

# Create Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)  # Used for securely signing the session

# OAuth Setup
oauth = OAuth(app)

# Keyrock OAuth2 configuration
keyrock = oauth.register(
    name='keyrock',
    # Set these in your environment or config file
    client_id=os.getenv('OAUTH2_CLIENT_ID'),
    client_secret=os.getenv('OAUTH2_CLIENT_SECRET'),
    access_token_url=os.getenv('OAUTH2_ACCESS_TOKEN_URL'),
    authorize_url=os.getenv('OAUTH2_AUTHORIZE_URL'),
    client_kwargs={'scope': 'openid profile email'},
)

@app.route('/')
def home():
    """ 
    route for printing user information
    """
    email = dict(session).get('email', None)
    return f'Hello, {email}! <a href="/login">Login</a>' if not email else f'Welcome back, {email}! <a href="/logout">Logout</a>'

print(keyrock)
# Login route
@app.route('/login')
def login():
    """
    login route which forwards to Keyrock for authentication and authorization
    """
    session['nonce'] = str(uuid.uuid4())
    session['state'] = str(uuid.uuid4())
    redirect_uri = url_for('authorize', _external=True)

    return keyrock.authorize_redirect(
        redirect_uri,
        prompt='login',
        state=session['state'],
        nonce=session['nonce']
    )

# OAuth2 callback route
@app.route('/authorize')
def authorize():
    """
    authorize endpoint which handles the callback from Keyrock and requests with
    the access token given by Keyrock the user information and sets the session 
    with the user information
    """
    # Check if the state exists in the session
    if 'state' not in session:
        return "State is missing in session!", 400  # Handle missing state

    # Check if the state matches
    if request.args.get('state') != session['state']:
        return "State does not match!", 400  # Handle the error as you see fit

    token = keyrock.authorize_access_token()
    
    if not token['access_token']:
        return "Access token is missing!", 400  # Handle the error as you see fit
    
    if token:
        headers = {'Authorization': f"Bearer {token['access_token']}"}
        response = requests.get(os.getenv('OAUTH2_USERINFO_URL'), headers=headers)

        if response.status_code == 200:
            user_info = response.json()
            # assign user information to session, in this case email to showcase the protocol
            session['email'] = user_info['email']
        else:
            return f"Failed to fetch user info: {response.status_code} - {response.text}"

    # redirects back to home page with user information assigned to session
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    """
    logout route which clears the session and redirects to the home page
    """
    session.clear()
    request_url = f"{os.getenv('OAUTH2_LOGOUT_URL')}?_method=DELETE&client_id={os.getenv('OAUTH2_CLIENT_ID')}" 
    return redirect(request_url)

if __name__ == '__main__':
    app.run(debug=True, port=5656)
