from flask import Flask,redirect,url_for,session,request,jsonify
from flaskext.mysql import MySQL
import mysql.connector
import base64
import requests
import os

app = Flask(__name__)
app.secret_key = "secret_key"
IDP_BASE_URL = os.environ.get('IDP_BASE_URL')
CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
REDIRECT_URI = 'http://localhost:5000'  #Has to be this URI ??
SCOPE = 'openid'
STATE = '1234567890' 

mysql = MySQL()
mysql.init_app(app)

# Database configuration
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
app.config['MYSQL_DATABASE_PORT'] = 3307  
app.config['MYSQL_DATABASE_USER'] = 'root'
app.config['MYSQL_DATABASE_PASSWORD'] = 'password' #change this all to environment variables
app.config['MYSQL_DATABASE_DB'] = 'auth'

def get_db_connection():
    conn = mysql.connect()
    return conn


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
            token_type = token_data.get('token_type')

            userinfo_endpoint = f"{IDP_BASE_URL}/userinfo"
            headers = {'Authorization': f"{token_type} {access_token}"}
            userinfo_response = requests.get(userinfo_endpoint, headers=headers)
            userinfo = userinfo_response.json()

            # Store user information in the database
            db_connection = get_db_connection()
            cursor = db_connection.cursor()
            cursor.execute("INSERT INTO users (email, access_token, refresh_token) VALUES (%s, %s, %s)", (userinfo['email'], access_token, userinfo.get('refresh_token')))
            db_connection.commit()
            cursor.close()
            db_connection.close()
            
            session['access_token'] = access_token
            return redirect(url_for('register'))
        else:
            jsonify({'error': 'Failed to obtain access token'}), 500
            return redirect(url_for('signin'))
    else:
        return redirect(url_for('signin'))

@app.route('/v1/signin') #redirect to the idp
def signin():
    authorization_url = f"{IDP_BASE_URL}/authorize?response_type=code&client_id={CLIENT_ID}&state={STATE}&scope={SCOPE}&redirect_uri={REDIRECT_URI}"
    response = requests.get(authorization_url)
    print(response)
    return redirect(authorization_url)

# @app.route('/callback')
# def callback():
#     return redirect(url_for('signin'))
    
@app.route('/register')
def register():
    access_token = session.get('access_token')
    if access_token:
        # User is authenticated, you can perform actions here
        # check if the user is already in database
        db_connection = get_db_connection()
        cursor = db_connection.cursor()
        cursor.execute("SELECT * FROM users WHERE access_token = %s", (access_token,))
        user = cursor.fetchone()
        cursor.close()
        db_connection.close()
        if user:
            return 'Welcome to the homepage!'
        else:
            return 'Please register'
    else:
        # User is not authenticated, redirect to login
        return redirect(url_for('signin'))

if __name__ == '__main__':
    app.run(debug=True)