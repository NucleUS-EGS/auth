from flask import Flask,redirect,url_for,session,request,jsonify,abort, make_response
from flaskext.mysql import MySQL
from functools import wraps
import base64
import requests
import base64
import os
import json

app = Flask(__name__)
app.secret_key = "secret_key"
IDP_BASE_URL = os.environ.get('IDP_BASE_URL')
CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
FRONTEND_URL = os.environ.get('FRONTEND_BASE_URL')
REDIRECT_URI = 'http://localhost:5000'  
SCOPE = 'openid'
STATE = '1234567890' 

mysql = MySQL()
mysql.init_app(app)

# Database configuration
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
app.config['MYSQL_DATABASE_PORT'] = 3308  
app.config['MYSQL_DATABASE_USER'] = 'root'
app.config['MYSQL_DATABASE_PASSWORD'] = 'password' #change this all to environment variables
app.config['MYSQL_DATABASE_DB'] = 'auth'

def get_db_connection():
    conn = mysql.connect()
    return conn

#API_KEY checking in the database
def verify_api_key(api_key):
    db_connection = get_db_connection()
    cursor = db_connection.cursor()
    query = "SELECT COUNT(*) FROM APIKEYS WHERE api_key = %s"

    cursor.execute(query,(api_key,))
    result = cursor.fetchone()
    cursor.close()
    db_connection.close()

    if result[0]>0:
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
            #print(userinfo.get('email'))

            # Store user information in the database
            db_connection = get_db_connection()
            cursor = db_connection.cursor()
            cursor.execute("SELECT COUNT(*) FROM users WHERE email = %s", (userinfo['email'],))
            exists = cursor.fetchone()[0]

            if exists:
        # Update existing user's tokens
                cursor.execute("UPDATE users SET access_token = %s, refresh_token = %s WHERE email = %s",
                            (access_token, refresh_token, userinfo['email']))
            else:
        # Insert new user
                cursor.execute("INSERT INTO users (email, access_token, refresh_token) VALUES (%s, %s, %s)",
                            (userinfo['email'], access_token, refresh_token))

            db_connection.commit()
            cursor.close()
            db_connection.close()
            
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
@require_api_key
def signin():
    print(request.headers)
    authorization_url = f"{IDP_BASE_URL}/authorize?response_type=code&client_id={CLIENT_ID}&state={STATE}&scope={SCOPE}&redirect_uri={REDIRECT_URI}"
    #response = requests.get(authorization_url)
    #print(response)
    return redirect(authorization_url)
    
@app.route('/v1/register')
@require_api_key
def register():
    access_token = session.get('access_token')
    if access_token:

        #NUCLEO UPDATE , ECT DEFAULT FOR TEST MODE
        # nucleo = request.form.get('nucleo')
        # if not nucleo:
        #     return jsonify({"error": "Nucleo value is required"}), 400
        nucleo = 'ECT'
        db_connection = get_db_connection()
        cursor = db_connection.cursor()
        cursor.execute("SELECT * FROM users WHERE access_token = %s", (access_token,))
        user = cursor.fetchone()
        if user:
            session['email'] = user[1]
            session['access_token'] = user[3]
            # Update the user with the nucleo value
            cursor.execute("UPDATE users SET nucleo = %s WHERE access_token = %s", (nucleo, access_token))
            db_connection.commit()
            cursor.close()
            db_connection.close()
            # Redirect to the check function to handle further logic
            return redirect(url_for('checkUser'))
        else:
            cursor.close()
            db_connection.close()
            session['type'] = 'register'
            return jsonify({"message": "User not found"}), 404
    else:
        # User is not authenticated, redirect to login
        return redirect(url_for('signin'))

@app.route('/v1/check')
def checkUser():
    if session.get('access_token'):
        db_connection = get_db_connection()
        cursor = db_connection.cursor()
        #print(session.get('email'))
        cursor.execute("SELECT Nucleo FROM users WHERE email = %s", (session.get('email'),))
        result = cursor.fetchone()
        cursor.close()
        db_connection.close()

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