from email import message
from email.policy import default
from enum import IntEnum, unique

from matplotlib import use
from flask import Flask, request, render_template, redirect, url_for, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
import sys
import hashlib
import socket
import os
import json
import time
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = "Dale has his own ways"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
db = SQLAlchemy(app)

FILE_PATH = "messages.csv"

class UserState(IntEnum):
    GROUNDED = 0
    IDENTIFIED = 1
    AUTHENTICATED = 2

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(32), index = True, unique=True)
    password_hash = db.Column(db.String(128), default=None)
    user_state = db.Column(db.Integer, default=UserState.GROUNDED)
    last_endpoint = db.Column(db.String(16), default=None)

    def hash_password(self, username: str, password: str) -> None:
        salt = username.encode('utf-8')
        self.password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=128)

    def verify_password(self, username:str, password: str) -> bool:
        salt = username.encode('utf-8')
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=128)
        if password_hash == self.password_hash:
            return True
        else:
            return False

    def generate_auth_token(self, expires_in=600):
        return jwt.encode(
            {'id': self.id, 'exp': time.time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],
                              algorithms=['HS256'])
        except:
            return
        return User.query.get(data['id'])

def write_to_file(username: str, timestamp: str, message: str) -> None:
    file = open(FILE_PATH, "a")
    file.write(timestamp + ", " + username + ", " + message + "\n")
    file.close()
        
@app.route('/identify', methods=['POST'])
def identify():
    message_type = request.json.get('message_type')
    username = request.json.get('username')
    current_ip = request.remote_addr

    if message_type is None or message_type != "IDENTIFY":
        abort(400)
    
    if username is None:
        abort(400)
    
    status_message = ""
    user: User = User.query.filter_by(username=username).first()
    if user is None:
        try:
            user = User(username=username, user_state=UserState.IDENTIFIED, last_endpoint=current_ip)
            db.session.add(user)
            db.session.commit()
        except Exception as e:
            return jsonify({"status_message": str(e), "status_code": 200})

        status_message = "New User Identified"
    else:
        user.last_endpoint = current_ip
        user.user_state = UserState.IDENTIFIED
        db.session.add(user)
        db.session.commit()
        status_message = "Existing User Identified"
    
    token = user.generate_auth_token(600)
    
    return jsonify({'token': token, "status_message": status_message, "status_code": 200})

@app.route('/authenticate', methods=['POST'])
def authenticate():
    message_type = request.json.get('message_type')
    username = request.json.get('username')
    password = request.json.get('password')
    token = request.json.get('token')
    current_ip = request.remote_addr

    if message_type is None or message_type != "AUTHENTICATE":
        abort(400)
    
    if username is None or password is None:
        abort(400)

    user: User = User.query.filter_by(username=username).first()

    if user is None:
        abort(400)

    if user.last_endpoint != current_ip or user.user_state != UserState.IDENTIFIED:
        return jsonify({"status_message": "Please identify first", "status_code": 200})
    else:
        if user.password_hash == None:
            user.hash_password(username=username, password=password)
            user.user_state = UserState.AUTHENTICATED
            db.session.add(user)
            db.session.commit()
            return jsonify({"status_message": "New user password registered", "status_code": 200})
        else:
            if user.verify_password(username=username, password=password):
                user.user_state = UserState.AUTHENTICATED
                db.session.add(user)
                db.session.commit()
                return jsonify({"status_message": "Authentication Successful", "status_code": 200})
            else:
                return jsonify({"status_message": "Authentication Failed", "status_code": 200})

        return jsonify({"status_message": "New User Identified", "status_code": 200})

    # user = User.verify_auth_token(token=token)
    # if not user:
    #     return jsonify({"status_message": "Token Expired. Please generate new token!", "status_code": 200})

    # user.user_state = UserState.AUTHENTICATED
    # db.session.add(user)
    # db.session.commit()
    
    return jsonify({"status_message": "Login Successful", "status_code": 200})

@app.route('/message', methods=['POST'])
def receive_message():
    message_type = request.json.get('message_type')
    username = request.json.get('username')
    message = request.json.get('message')
    current_ip = request.remote_addr

    if message_type is None or message_type != "MESSAGE":
        abort(400)
    
    if username is None or message is None:
        abort(400)

    user: User = User.query.filter_by(username=username).first()
    if user is None:
        abort(400)

    if user.last_endpoint != current_ip or user.user_state != UserState.AUTHENTICATED:
        return jsonify({"status_message": "Please identify and authenticate first", "status_code": 200})
    else:
        if message == "" or message == "logout":
            message = "logout"
            user.user_state = UserState.GROUNDED
            db.session.add(user)
            db.session.commit()
        write_to_file(username=username, timestamp=str(time.time()), message=message)
    
    return jsonify({"status_message": "Message Received", "status_code": 200})

if __name__ == "__main__":
    print(socket.gethostbyname(socket.gethostname()))
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(host=socket.gethostbyname(socket.gethostname()), port=int(sys.argv[1]), debug=True)
