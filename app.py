from flask import Flask,redirect,url_for,session,request
import base64
import requests

app = Flask(__name__)
secret_key = "secret_key"
IDP_BASE_URL = 'https://wso2-gw.ua.pt'
CLIENT_ID = 'agh44RajMJcYvCIq3lSMrutfPJ0a'
CLIENT_SECRET = 'WJckU0FSb41rsJHLnFPYqBFvSZoa'
REDIRECT_URI = 'http://localhost:5000'
SCOPE = 'openid'
STATE = '1234567890' 
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
    if response.status_code == 200:
        token_data = response.json()
        access_token = token_data.get('access_token')
        token_type = token_data.get('token_type')

        userinfo_endpoint = f"{IDP_BASE_URL}/userinfo"
        headers = {'Authorization': f"{token_type} {access_token}"}
        userinfo_response = requests.get(userinfo_endpoint, headers=headers)
        userinfo = userinfo_response.json()
        print(userinfo)

        
        
    return 'Hello, world! This route does not require authentication.'

@app.route('/signin') #redirect to the idp
def signin():
    authorization_url = f"{IDP_BASE_URL}/authorize?response_type=code&client_id={CLIENT_ID}&state={STATE}&scope={SCOPE}&redirect_uri={REDIRECT_URI}"
    response = requests.get(authorization_url)
    print(response)
    return redirect(authorization_url)


# @app.route('/entering')
# def entering():
#     code = request.args.get('code')
#     if code:
#         # Exchange the authorization code for an access token
#         token_endpoint = f"{IDP_BASE_URL}/token"
#         data = {
#             'grant_type': 'authorization_code',
#             'code': code,
#             'redirect_uri': REDIRECT_URI
#         }
#         headers = {'Authorization': f"Basic {CLIENT_ID}:{CLIENT_SECRET}"}
#         response = requests.post(token_endpoint, data=data, headers=headers)

#         if response.status_code == 200:
#             token_data = response.json()
#             access_token = token_data.get('access_token')
#             session['access_token'] = access_token  # Store the access token in session
#             userinfo_endpoint = f"{IDP_BASE_URL}/userinfo"
#             headers = {'Authorization': f"Bearer {access_token}"}
#             userinfo_response = requests.get(userinfo_endpoint, headers=headers)
#             userinfo = userinfo_response.json()

#             #Check if is already registered
#             return redirect(url_for('dashboard'))
#             #if not registered
#             return redirect(url_for('register'))
#         else:
#             return 'Failed to obtain access token'
#     else:
#         return 'Authorization code not found in callback URL'

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