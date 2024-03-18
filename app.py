from flask import Flask,redirect,url_for,session,request
from flaskext.mysql import MySQL
import mysql.connector
import base64
import requests
import os
import json

app = Flask(__name__)
secret_key = "secret_key"
IDP_BASE_URL = os.environ.get('IDP_BASE_URL')
CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
REDIRECT_URI = 'http://localhost:5000'
SCOPE = 'openid'
STATE = '1234567890' 
mysql = MySQL()
mysql.init_app(app)
#database configuration
db_config = {
    'host':'localhost',
    'port' :  3306,
    'user':'root',
    'password':'password',
    'database':'auth'
}

def get_db_connection():
    conn = mysql.connector.connect(**db_config)
    return conn


# Route without authentication
@app.route('/') #choose the idp (only UA is available)
def index():
    byteData = f"{CLIENT_ID}:{CLIENT_SECRET}".encode('utf-8')
    encoded = base64.b64encode(byteData).decode('utf-8')
    authorization_url = f"{IDP_BASE_URL}/token?grant_type=authorization_code&code={request.args.get('code')}&redirect_uri={REDIRECT_URI}"
    headers = {
        'Authorization': f"Basic {encoded}",
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    response = requests.post(authorization_url, headers=headers)

    result = {}
    if response.status_code == 200:
        token_data = response.json()
        result['token'] = token_data
        access_token = token_data.get('access_token')
        token_type = token_data.get('token_type')

        userinfo_endpoint = f"{IDP_BASE_URL}/userinfo"
        headers = {'Authorization': f"{token_type} {access_token}"}
        userinfo_response = requests.get(userinfo_endpoint, headers=headers)
        userinfo = userinfo_response.json()
        result['userinfo'] = userinfo
        
        print(result)
        
    return json.dumps(result)

@app.route('/signin') #redirect to the idp
def signin():
    authorization_url = f"{IDP_BASE_URL}/authorize?response_type=code&client_id={CLIENT_ID}&state={STATE}&scope={SCOPE}&redirect_uri={REDIRECT_URI}"
    response = requests.get(authorization_url)
    print(response)
    return redirect(authorization_url)

@app.route('/register')
def dashboard():
    access_token = session.get('access_token')
    if access_token:
        # User is authenticated, you can perform actions here
        return 'Welcome to the homepage!'
    else:
        # User is not authenticated, redirect to login
        return redirect(url_for('signin'))

if __name__ == '__main__':
    app.run(debug=True)