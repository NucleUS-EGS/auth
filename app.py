import flask
from flask import Flask,redirect,url_for,session,request,jsonify,abort, make_response
from functools import wraps
import base64
import requests
import base64
import os
from sqlalchemy.orm import sessionmaker
from sqlalchemy import func
from dotenv import load_dotenv
load_dotenv()

from database import *


app = Flask(__name__)
app.secret_key = "secret_key"
IDP_BASE_URL = os.environ.get('IDP_BASE_URL')
CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
FRONTEND_URL = os.environ.get('FRONTEND_BASE_URL')
REDIRECT_URI = os.environ.get('IDP_REDIRECT_URI')
SCOPE = 'openid'
STATE = '1234567890' 

# mysql = MySQL()
# mysql.init_app(app)

Session = sessionmaker(bind=engine)
session_BD = Session()
# Database configuration
app.config['MYSQL_DATABASE_HOST'] = os.environ.get('HOST')
app.config['MYSQL_DATABASE_PORT'] = os.environ.get('PORT')
app.config['MYSQL_DATABASE_USER'] = os.environ.get('USER_NAME')
app.config['MYSQL_DATABASE_PASSWORD'] = os.environ.get('PASSWORD')
app.config['MYSQL_DATABASE_DB'] = os.environ.get('DATABASE')

with app.app_context():
    exists = session_BD.query(APIKEYS.apiKey).first() is not None
    if not exists:
        api_key = os.environ.get('API_KEY')
        new_api_key = APIKEYS(apiKey=api_key)
        session_BD.add(new_api_key)
        session_BD.commit()
    
    session_BD.close()


# def get_db_connection():
#     conn = mysql.connect()
#     return conn

#API_KEY checking in the database
def verify_api_key(api_key):
    
    count = session_BD.query(func.count()).filter(APIKEYS.api_key == api_key).scalar()

    session_BD.close()

    if count>0:
        return True
    else:
        return False


#API key verification function
def require_api_key(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        print(request.headers)
        api_key = request.args.get('token')
        #decode the api key
        api_key = api_key.encode('utf-8')
        api_key = base64.b64decode(api_key).decode('utf-8')
        print(api_key)
        print(f"API key received: {api_key}")
        if not api_key or not verify_api_key(api_key):
            abort(401)
        print(f"API key {api_key} verified successfully.")  
        return func(*args,**kwargs)
    return decorated_function



# Route without authentication
@app.route('/') #choose the idp (only UA is available)
def index():
    code = request.args.get('code')
    if code:
        code = request.args.get('code')
        byteData = f"{CLIENT_ID}:{CLIENT_SECRET}".encode('utf-8')
        encoded = base64.b64encode(byteData).decode('utf-8')
        token_url = f"{IDP_BASE_URL}/token"
        headers = {
            'Authorization': f"Basic {encoded}",
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI
        }
        response = requests.post(token_url, headers=headers, data=data)
        if response.status_code == 200:
            token_data = response.json()
            access_token = token_data.get('access_token')
            refresh_token = token_data.get('refresh_token')
            token_type = token_data.get('token_type')
            expires_in = token_data.get('expires_in')

            userinfo_endpoint = f"{IDP_BASE_URL}/userinfo"
            headers = {'Authorization': f"{token_type} {access_token}"}
            userinfo_response = requests.get(userinfo_endpoint, headers=headers)
            userinfo = userinfo_response.json()
            email = userinfo.get('email')

            # Store user information in the database
            
            exists = session_BD.query(User).filter(User.email == userinfo['email']).count()


            if exists:
        # Update existing user's tokens
                session_BD.query(User).filter(User.email == userinfo['email']).update(
                    {"access_token": access_token, "refresh_token": refresh_token}
                )
            else:
        # Insert new user
                new_user = User(email=email, access_token=access_token, refresh_token=refresh_token)
                session_BD.add(new_user)

            session_BD.commit()
            session_BD.close()
            session['email'] = userinfo['email']
            session['access_token'] = access_token

            resp = make_response(redirect(url_for('checkUser')))
            resp.set_cookie('AUTH_SERVICE_EMAIL', userinfo['email'])
            resp.set_cookie('AUTH_SERVICE_ACCESS_TOKEN', access_token)
            return resp
        else:
            jsonify({'error': 'Failed to obtain access token'}), 500
            return redirect(url_for('signin'))
    else:
        return redirect(url_for('signin'))

@app.route('/v1/signin') #redirect to the idp
#@require_api_key
def signin():
    # signin for nucleos
    if flask.request.method == 'POST':
        # get request body
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400
        # check if user exists in the database
        user = session_BD.query(User).filter(User.email == email).first()
        if user:
            session['email'] = user[1]
            session['access_token'] = user[3]
        else:
            # insert new user
            nucleo = Nucleo(email=email, password=password)
            session_BD.add(nucleo)
            session_BD.commit()
            session['email'] = email

        session_BD.close()
        return jsonify({
            "message": "User signed in successfully",
            "email": session.get('email')
        }), 200
    
    # signin for users
    print(request.headers)
    authorization_url = f"{IDP_BASE_URL}/authorize?response_type=code&client_id={CLIENT_ID}&state={STATE}&scope={SCOPE}&redirect_uri={REDIRECT_URI}"
    #response = requests.get(authorization_url)
    #print(response)
    return redirect(authorization_url)
    
@app.route('/v1/register')
#@require_api_key
def register():
    access_token = session.get('access_token')
    if access_token:

        #NUCLEO UPDATE , ECT DEFAULT FOR TEST MODE
        # nucleo = request.form.get('nucleo')
        # if not nucleo:
        #     return jsonify({"error": "Nucleo value is required"}), 400
        nucleo = 'ECT'
        user = session_BD.query(User).filter(User.access_token == access_token).first() 
        if user:
            session['email'] = user[1]
            session['access_token'] = user[3]
            # Update the user with the nucleo value
            session_BD.query(User).filter(User.access_token == access_token).update({"nucleo": nucleo})
            session_BD.commit()
            # Redirect to the check function to handle further logic
            return redirect(url_for('checkUser'))
        else:
            session_BD.close()
            session['type'] = 'register'
            return jsonify({"message": "User not found"}), 404
    else:
        # User is not authenticated, redirect to login
        return redirect(url_for('signin'))

@app.route('/v1/check')
def checkUser():
    if session.get('access_token'):
        #print(session.get('email'))
        result = session_BD.query(User.nucleo).filter(User.email == session.get('email')).first()
        session_BD.close()
        if result:
            nucleo_assigned = result[0]
            if nucleo_assigned:
                # If 'nucleo' is assigned, return to the homepage
                resp = make_response(redirect(f"{FRONTEND_URL}"))
                resp.set_cookie('AUTH_SERVICE_STEP', 'loggedin')
                return resp
            else:
                # If 'nucleo' is not assigned, redirect to frontend registration page
                resp = make_response(redirect(f"{FRONTEND_URL}/register"))
                resp.set_cookie('AUTH_SERVICE_STEP', 'register')
                return resp
        else:
            # If user not found in the database, consider what you'd want to do here
            return jsonify({"message": "User not found"}), 404


if __name__ == '__main__':
    app.run(debug=True)