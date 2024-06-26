import flask
from flask import Flask,redirect,url_for,session,request,jsonify,abort, make_response
from functools import wraps
import base64
import requests
import base64
import os
import logging

from waitress import serve
from sqlalchemy.orm import sessionmaker
from sqlalchemy import func
from dotenv import load_dotenv

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

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


@app.route('/v1/idp')
def idp():
    access_token = request.args.get('access_token')
    refresh_token = request.args.get('refresh_token')
    token_type = request.args.get('token_type')
    expires_in = request.args.get('expires_in')
    email = request.args.get('email')

    user = session_BD.query(User).filter(User.email == email).first()
    if user:
        session_BD.query(User).filter(User.email == email).update(
            {"access_token": access_token, "refresh_token": refresh_token}
        )
        user_id = user.id
        user.access_token = access_token
        user.refresh_token = refresh_token
        session_BD.commit()
    else:
        new_user = User(email=email, access_token=access_token, refresh_token=refresh_token)
        session_BD.add(new_user)
        session_BD.commit()
        user_id = new_user.id

    session_BD.close()
    session['email'] = email
    session['access_token'] = access_token

    resp = make_response(redirect("/auth/"+url_for('checkUser')))
    resp.set_cookie('AUTH_SERVICE_EMAIL', email)
    resp.set_cookie('AUTH_SERVICE_USERNAME', email.split('@')[0])
    resp.set_cookie('AUTH_SERVICE_ACCESS_TOKEN', access_token)
    resp.set_cookie('AUTH_SERVICE_ID', str(user_id))  # Set the user ID cookie

    return resp

# R authentication
@app.route('/') #choose the idp (only UA is available)
def index():
    code = request.args.get('code')
    if code:
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

            user = session_BD.query(User).filter(User.email == userinfo['email']).first()
            if user:
                session_BD.query(User).filter(User.email == userinfo['email']).update(
                    {"access_token": access_token, "refresh_token": refresh_token}
                )
                user_id = user.id  # Fetch the user ID from the database
            else:
                new_user = User(email=email, access_token=access_token, refresh_token=refresh_token)
                session_BD.add(new_user)
                session_BD.commit()
                user_id = new_user.id  # Fetch the newly created user ID

            session_BD.close()
            session['email'] = userinfo['email']
            session['access_token'] = access_token

            resp = make_response(redirect("/auth/"+url_for('checkUser')))
            resp.set_cookie('AUTH_SERVICE_EMAIL', userinfo['email'])
            resp.set_cookie('AUTH_SERVICE_USERNAME', userinfo['email'].split('@')[0])
            resp.set_cookie('AUTH_SERVICE_ACCESS_TOKEN', access_token)
            resp.set_cookie('AUTH_SERVICE_ID', str(user_id))  # Set the user ID cookie

            return resp
        else:
            return jsonify({'error': 'Failed to obtain access token'}), 500
    else:
        return redirect("/auth/"+url_for('signin'))


@app.route('/v1/signin', methods=['GET', 'POST'])  # redirect to the idp
def signin():
    if request.method == 'POST':
        if not request.is_json:
            return jsonify({"error": "Request content must be JSON"}), 415

        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        user = session_BD.query(Nucleo).filter(Nucleo.email == email).first()
        if user:
            session['id'] = user.id
            session['email'] = user.email
            logger.debug(f"User {email} has already an account")
        else:
            nucleo = Nucleo(email=email, password=password)
            session_BD.add(nucleo)
            session_BD.commit()
            session['id'] = nucleo.id
            session['email'] = email
            logger.debug(f"User {email} created")
            

        session_BD.close()
        return jsonify({
            "message": "User signed in successfully",
            "id": session.get('id'),
            "email": session.get('email')
        }), 200
    
    authorization_url = f"{IDP_BASE_URL}/authorize?response_type=code&client_id={CLIENT_ID}&state={STATE}&scope={SCOPE}&redirect_uri={REDIRECT_URI}"
    return redirect(authorization_url)

    
@app.route('/v1/register', methods=['POST'])
#@require_api_key
def register():
    data = request.get_json()
    access_token = data.get("access_token")
    if access_token:
        user_nucleo = data.get('nucleo')
        if not user_nucleo:
            return jsonify({"error": "Nucleo value is required"}), 400

        user = session_BD.query(User).filter(User.access_token == access_token).first()
        if user:
            session['email'] = user.email
            session['access_token'] = user.access_token

            nucleo_email = f"{user_nucleo}@aauav.pt"
            nucleo = session_BD.query(Nucleo).filter(Nucleo.email == nucleo_email).first()

            user.nucleo = nucleo.id
            session_BD.commit()

            return jsonify({
                "message": "User registered successfully",
                "email": user.email,
                "nucleo": user_nucleo,
                "step": "loggedin"
            }), 200
        else:
            session_BD.close()
            session['type'] = 'register'
            return jsonify({"message": "User not found"}), 404
    else:
        return redirect("auth/"+url_for('signin'))

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
                resp = make_response(redirect(f"{FRONTEND_URL}register"))
                resp.set_cookie('AUTH_SERVICE_STEP', 'register')
                return resp
        else:
            # If user not found in the database, consider what you'd want to do here
            return jsonify({"message": "User not found"}), 404


@app.route('/v1/user', methods=['GET'])
def getUser():      
    token = request.args.get('access_token')
    if token:
        try:
            user = session_BD.query(User).filter(User.access_token == token).first()
            if user:
                nucleo = session_BD.query(Nucleo).filter(Nucleo.id == user.nucleo).first()
                if nucleo:
                    return jsonify({
                        "id": user.id,
                        "email": user.email,
                        "nucleo": nucleo.email
                    }), 200
                else:
                    return jsonify({"error": "Nucleo not found"}), 404
            else:
                return jsonify({"error": "User not found"}), 404
        except Exception as e:
            app.logger.error(f"Error occurred: {e}")
            return jsonify({"error": str(e)}), 500
        finally:
            session_BD.close()
    else:
        return jsonify({"error": "Access token not provided"}), 400

@app.route('/v1/nucleus')
def checkNucleus(): #return all nucleus in the database
    if flask.request.method == 'GET':
        try:
            nucleus_emails = session_BD.query(Nucleo.email).all()
            emails = [email.split('@')[0] for (email,) in nucleus_emails]
            return jsonify({"nucleus": emails}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            session_BD.close()


#gets users belonging to that nucleo
@app.route('/v1/students')
def getStudents():
    nucleo_id = request.args.get('nucleo_id')
   
    try:
        nucleo_id = int(nucleo_id)
        users = session_BD.query(User).filter(User.nucleo == nucleo_id).all() 
        user_list = [{"id": user.id, "email": user.email} for user in users]
        
        return jsonify({"users": user_list}), 200
    
    finally:
        session_BD.close()




HOST = os.environ.get('APP_HOST')
PORT = os.environ.get('APP_PORT')

if __name__ == '__main__':
    # serve(app, host=HOST, port=PORT)
    app.run(debug=True)