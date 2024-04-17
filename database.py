from sqlalchemy import create_engine
from sqlalchemy.engine import reflection
from sqlalchemy.orm import declarative_base
from db_config import db, get_db

print(get_db())
engine = create_engine(get_db())

# Base declarative class
Base = declarative_base()

# Define models
class User(Base):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    access_token = db.Column(db.String(255))
    refresh_token = db.Column(db.String(255))
    nucleo        = db.Column(db.String(255))

    # def __init__(self) -> None:
    #     super().__init__()

    def to_dict(self):
        return{
            'id' :self.id,
            'email': self.email,
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'nucleo': self.nucleo
        }

class Nucleo(Base):
    __tablename__ = 'nucleos'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))

    # def __init__(self) -> None:
    #     super().__init__()
    
    def to_dict(self):
        return{
            'id' : self.id,
            'email': self.email,
            'password': self.password
        }
    
class APIKEYS(Base):
    __tablename__ = 'apikeys'
    id = db.Column(db.Integer, primary_key=True)
    apiKey = db.Column(db.String(255))
    
    # def __init__(self) -> None:
    #     super().__init__()

    def to_dict(self):
        return {
            'id': self.id,
            'apiKey': self.apiKey
        }
    
insp = reflection.Inspector.from_engine(engine)


if not insp.has_table(APIKEYS.__tablename__):
    print(" * Creating database tables")
    Base.metadata.create_all(engine)
    