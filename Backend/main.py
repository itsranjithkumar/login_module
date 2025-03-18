from fastapi import FastAPI, Depends, HTTPException
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth, OAuthError
from config import CLIENT_ID, CLIENT_SECRET

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="add any string...")

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
    return {"message": "Please login"}

@app.get('/welcome')
def welcome(request: Request):
    return {"message": "Welcome"}

@app.get("/login")
async def login(request: Request):
    url = request.url_for('auth')
    return await oauth.google.authorize_redirect(request, url)

@app.get('/auth')
async def auth(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError as e:
        return {"error": e.error}
    user = token.get('userinfo')
    print(user)
    if user:
        request.session['user'] = dict(user)
    return {"access_token": token["access_token"], "token_type": "Bearer"}

@app.get('/logout')
def logout(request: Request):
    request.session.pop('user', None)
    request.session.clear()
    return RedirectResponse('/')