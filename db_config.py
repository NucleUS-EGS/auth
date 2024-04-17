import os
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy

load_dotenv()

def get_db():
    return f"mysql+pymysql://{os.environ.get('USER_NAME')}:{os.environ.get('PASSWORD')}@{os.environ.get('HOST')}:{os.environ.get('PORT')}/{os.environ.get('DATABASE')}"

def get_sqlalchemy_track_modifications():
    return False 

db_config = {
    'host': os.environ.get("HOST"),
    'port': os.environ.get("PORT"),
    'user': os.environ.get("USER_NAME"),
    'password': os.environ.get("PASSWORD"),
    'database': os.environ.get('DATABASE')
}

db = SQLAlchemy()