from fastapi import FastAPI, Depends, HTTPException
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth, OAuthError
from config import CLIENT_ID, CLIENT_SECRET

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="add any string...")

# Dictionary to store registered users
users = {}

oauth = OAuth()
oauth.register(
    name='google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    client_kwargs={
        'scope': 'email openid profile',
        'redirect_uri': 'http://localhost:8000/auth'
    }
)

@app.get("/")
def index(request: Request):
    return {"message": "Please login or signup"}

@app.get('/welcome')
def welcome(request: Request):
    return {"message": "Welcome"}

@app.get("/login")
async def login(request: Request):
    request.session['auth_type'] = 'login'
    url = request.url_for('auth')
    return await oauth.google.authorize_redirect(request, url)

@app.get("/signup")
async def signup(request: Request):
    request.session['auth_type'] = 'signup'
    url = request.url_for('auth')
    return await oauth.google.authorize_redirect(request, url)

@app.get('/auth')
async def auth(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError as e:
        return {"error": e.error}
    
    user_info = token.get('userinfo')
    if not user_info:
        return {"error": "Failed to get user info"}
    
    email = user_info.get('email')
    auth_type = request.session.get('auth_type', 'login')
    
    # Check if user exists
    user_exists = email in users
    
    if auth_type == 'signup':
        if user_exists:
            return {"error": "User already exists. Please login instead."}
        # Create new user
        users[email] = {
            'email': email,
            'name': user_info.get('name'),
            'picture': user_info.get('picture')
        }
        request.session['user'] = dict(user_info)
        return {
            "message": "Successfully signed up",
            "access_token": token["access_token"],
            "token_type": "Bearer",
            "user_info": users[email]
        }
    else:  # login
        if not user_exists:
            return {"error": "User not found. Please signup first."}
        request.session['user'] = dict(user_info)
        return {
            "message": "Successfully logged in",
            "access_token": token["access_token"],
            "token_type": "Bearer",
            "user_info": users[email]
        }

@app.get('/logout')
def logout(request: Request):
    request.session.pop('user', None)
    request.session.pop('auth_type', None)
    request.session.clear()
    return {"message": "Successfully logged out"}