from flask import Flask, redirect, url_for, session, request
from authlib.integrations.flask_client import OAuth
from authlib.jose import jwt

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
    client_id=os.getenv('OAUTH2_CLIENT_ID'),
    client_secret=os.getenv('OAUTH2_CLIENT_SECRET'),
    server_metadata_url=f"{os.getenv('OIDC_ISSUER_URL')}/.well-known/openid-configuration",
    client_kwargs={'scope': 'openid profile email jwt'},
)

def validate_id_token(id_token, nonce):
    try:
        # Fetch JWKS (public keys) from Keyrock
        jwks_url = f"{os.getenv('OIDC_ISSUER_URL')}/certs"
        jwks = requests.get(jwks_url).json()
        
        claims = jwt.decode(
            id_token,
            jwks,  # validate token signature against JWKS
            claims_options={
                'iss': {'essential': True, 'value': os.getenv('OIDC_ISSUER_URL')},
                'aud': {'essential': True, 'value': os.getenv('OAUTH2_CLIENT_ID')},
                'nonce': {'essential': True, 'value': nonce},  # Ensure the nonce matches
            },
        )
        return claims
    except Exception as e:
        print(f"ID Token validation failed: {str(e)}")
        return None

@app.route('/')
def home():
    """ 
    route for printing user information
    """
    email = dict(session).get('email', None)
    tenant = dict(session).get('tenant', None)

    return f'Hello, {email}! <a href="/login">Login</a>' if not email else f'Welcome back, {email}. You are associated to {tenant}! <a href="/logout">Logout</a>'

print(keyrock)
# Login route
@app.route('/login')
def login():
    """
    login route which forwards to Keyrock for authentication and authorization
    """
    session['nonce'] = str(uuid.uuid4())
    session['state'] = "oic"
    redirect_uri = url_for('authorize', _external=True)

    return keyrock.authorize_redirect(
        redirect_uri,
        prompt='login',
        state=session['state'],
        nonce=session['nonce'],
        response_type='id_token',
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
    
    claims = validate_id_token(request.args.get('id_token'), session['nonce'])
    if not claims:
        return "ID Token validation failed!", 400
    
    session['email'] = claims['email']
    session['tenant'] = claims['extra']['tenant']

    # redirects back to home page with user information assigned to session
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    """
    logout route which clears the session and redirects to the home page
    """
    session.clear()
    request_url = f"{os.getenv('OAUTH2_LOGOUT_URL')}?_method=DELETE&client_id={os.getenv('OAUTH2_CLIENT_ID')}" 
    print(request_url)
    return redirect(request_url)

if __name__ == '__main__':
    app.run(debug=True, port=5656)
