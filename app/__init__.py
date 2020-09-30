from flask import Flask
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from os import environ 
from sqlalchemy import Table, Column, Integer, String, ForeignKey


app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] =  environ.get('DBURL')
SECRET = environ.get('SECRET')
db = SQLAlchemy(app)
migrate = Migrate(app, db)


from app import views

class UserModel(db.Model):
    __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True)
    fingerprint = db.Column(db.String())
    login = db.Column(db.String())
    password_hash = db.Column(db.String())
    status = db.Column(db.String())
    refresh_token = db.Column(db.String())

    def __repr__(self):
        return f"<User {self.login}>"

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __init__(self, login, password):
        self.login = login
        self.password_hash = set_password(password)


def get_user_by_pk(pk):
    return db.session.query(UserModel).get(pk)

def user_login(login, password):
    user = s.query(UserModel).filter_by(login=login).first()
    if user and user.check_password(password):
        return db.session.query(UserModel).get(pk)
    return None
    