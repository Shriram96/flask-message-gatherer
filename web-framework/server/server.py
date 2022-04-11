from enum import IntEnum
import secrets

from matplotlib import use
from flask import Flask, request, render_template, redirect, url_for, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
import sys
import socket
import os
import time
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_urlsafe(16)
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
    id              = db.Column(db.Integer, primary_key = True)
    username        = db.Column(db.String(32), index = True, unique=True)
    state           = db.Column(db.Integer, default=UserState.GROUNDED)
    last_endpoint   = db.Column(db.String(16), default=None)

    def gate_keeper(self, last_endpoint, state) -> bool:
        endpoint_check      = (self.last_endpoint == last_endpoint)
        user_state_check    = (self.state & state)

        return bool(endpoint_check and user_state_check)

    def generate_auth_token(self, expires_in=600):
        return jwt.encode({'id': self.id, 'exp': time.time() + expires_in}, app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return None
        return User.query.get(data['id'])

def write_to_file(username: str, timestamp: str, message: str) -> None:
    file = open(FILE_PATH, "a")

    file.write(timestamp + ", " + username + ", " + message + "\n")
    file.close()
        
@app.route('/identify', methods=['POST'])
def identify():
    message_type    = request.json.get('message_type')
    username        = request.json.get('username')
    current_ip      = request.remote_addr

    status_message  = ""

    if message_type is None or message_type != "IDENTIFY":
        abort(400)
    
    if username is None:
        abort(400)
    
    user: User = User.query.filter_by(username=username).first()
    if user is None:
        try:
            user = User(username=username, state=UserState.IDENTIFIED, last_endpoint=current_ip)
        except Exception as e:
            return jsonify({"status_message": str(e), "status_code": 200})

        status_message = "New User Identified"
    else:
        user.last_endpoint = current_ip
        user.state = UserState.IDENTIFIED
        db.session.add(user)
        db.session.commit()
        status_message = "Existing User Identified"

    db.session.add(user)
    db.session.commit()
    
    token = user.generate_auth_token(600)
    
    return jsonify({'token': token, "status_message": status_message, "status_code": 200})

@app.route('/authenticate', methods=['POST'])
def authenticate():
    message_type    = request.json.get('message_type')
    token           = request.json.get('token')
    current_ip      = request.remote_addr

    status_message  = ""

    if message_type is None or message_type != "AUTHENTICATE":
        abort(400)

    user: User = User.verify_auth_token(token=token)
    if not user:
        return jsonify({"status_message": "Token Expired. Please identify!", "status_code": 200})

    if user.gate_keeper(current_ip, UserState.IDENTIFIED | UserState.AUTHENTICATED):
        user.state      = UserState.AUTHENTICATED
        status_message  = "Authentication Successful!"
    else:
        user.state      = UserState.GROUNDED
        status_message  = "Please identify!"

    db.session.add(user)
    db.session.commit()
    
    return jsonify({"status_message": status_message, "status_code": 200})

@app.route('/message', methods=['POST'])
def receive_message():
    message_type    = request.json.get('message_type')
    token           = request.json.get('token')
    message         = request.json.get('message')
    current_ip      = request.remote_addr

    if message_type is None or message_type != "MESSAGE":
        abort(400)
    
    if message is None:
        abort(400)

    user: User = User.verify_auth_token(token=token)
    if not user:
        return jsonify({"status_message": "Token Expired. Please identify!", "status_code": 200})

    if user.gate_keeper(current_ip, UserState.AUTHENTICATED):
        if message == "" or message == "logout":
            message     = "logout"
            user.state  = UserState.GROUNDED
        write_to_file(username=user.username, timestamp=str(time.time()), message=message)
    else:
        return jsonify({"status_message": "Please identify and authenticate first", "status_code": 200})
    
    db.session.add(user)
    db.session.commit()

    return jsonify({"status_message": "Message Received", "status_code": 200})

if __name__ == "__main__":
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(host=socket.gethostbyname(socket.gethostname()), port=int(sys.argv[1]), debug=True)
