from enum import IntEnum
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from hashlib import pbkdf2_hmac
from http import HTTPStatus
from jwt import decode, encode
from threading import Lock
from os.path import exists
from secrets import token_urlsafe
from sys import argv
from time import time

app = Flask(__name__)
app.config['SECRET_KEY'] = token_urlsafe(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)

FILE_PATH = "messages.csv"
FILE_LOCK = Lock()


class UserState(IntEnum):
    GROUNDED = 0
    IDENTIFIED = 1
    AUTHENTICATED = 2


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True, unique=True)
    password_hash = db.Column(db.String(128), default=None)
    state = db.Column(db.Integer, default=UserState.GROUNDED)
    last_endpoint = db.Column(db.String(16), default=None)

    def gate_keeper(self, last_endpoint, state) -> bool:
        endpoint_check = (self.last_endpoint == last_endpoint)
        user_state_check = (self.state & state)

        return bool(endpoint_check and user_state_check)

    def hash_password(self, username: str, password: str) -> None:
        salt = username.encode('utf-8')
        self.password_hash = pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=128)

    def verify_password(self, username:str, password: str) -> bool:
        salt = username.encode('utf-8')
        password_hash = pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=128)
        if password_hash == self.password_hash:
            return True
        else:
            return False

    def generate_auth_token(self, expires_in=600):
        return encode({'id': self.id, 'exp': time() + expires_in}, app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_auth_token(token):
        try:
            data = decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except Exception as e:
            print("JWT Decoding Exception", str(e))
            return None
        return User.query.get(data['id'])


def write_to_file(username: str, timestamp: str, message: str) -> None:
    with FILE_LOCK:
        file = open(FILE_PATH, "a")

        file.write(timestamp + ", " + username + ", " + message + "\n")
        file.close()


@app.route('/identify', methods=['POST'])
def identify():
    message_type = request.json.get('message_type')
    username = request.json.get('username')
    current_ip = request.remote_addr

    status_message = ""
    status: HTTPStatus = HTTPStatus.OK

    while True:

        if message_type is None or message_type != "IDENTIFY":
            status = HTTPStatus.BAD_REQUEST
            status_message = "Invalid or missing 'message_type'"
            break

        if username is None:
            status = HTTPStatus.BAD_REQUEST
            status_message = "Missing 'username'"
            break

        user: User = User.query.filter_by(username=username).first()
        if user is None:
            try:
                user = User(username=username, state=UserState.IDENTIFIED, last_endpoint=current_ip)
            except Exception as e:
                status = HTTPStatus.SERVICE_UNAVAILABLE
                status_message = "Unable to create new user"
                break
            status = HTTPStatus.CREATED
            status_message = "New User Created"
        else:
            user.last_endpoint = current_ip
            user.state = UserState.IDENTIFIED
            status = HTTPStatus.ACCEPTED
            status_message = "Existing User Identified"

        db.session.add(user)
        db.session.commit()
        break

    return jsonify(
        {
            "status_message": status_message,
            "status_code": status.value,
            "status_description": status.description
        }
    )


@app.route('/authenticate', methods=['POST'])
def authenticate():
    message_type = request.json.get('message_type')
    username = request.json.get('username')
    password = request.json.get('password')
    current_ip = request.remote_addr

    token = ""
    status_message = ""
    status: HTTPStatus = HTTPStatus.OK

    while True:
        if message_type is None or message_type != "AUTHENTICATE":
            status = HTTPStatus.BAD_REQUEST
            status_message = "Invalid or missing 'message_type'"
            break

        if username is None:
            status = HTTPStatus.BAD_REQUEST
            status_message = "Missing 'username'"
            break

        if password is None:
            status = HTTPStatus.BAD_REQUEST
            status_message = "Missing 'password'"
            break

        user: User = User.query.filter_by(username=username).first()
        if not user:
            status = HTTPStatus.UNAUTHORIZED
            status_message = "User not found. Please identify"
            break

        if user.gate_keeper(current_ip, UserState.IDENTIFIED | UserState.AUTHENTICATED):
            if user.password_hash == None:
                user.hash_password(username=username, password=password)
                status = HTTPStatus.CREATED
                status_message = "New User password authenticated. Your token has been generated, {}!".format(user.username)
            elif user.verify_password(username=username, password=password):
                status = HTTPStatus.ACCEPTED
                status_message = "Existing User password authenticated. Your token has been generated, {}!".format(user.username)
            else:
                status = HTTPStatus.FORBIDDEN
                user.state = UserState.IDENTIFIED
                status_message = "Authentication Failed!. Please try again, {}!".format(user.username)
                break

            token = user.generate_auth_token(600)
            user.state = UserState.AUTHENTICATED
        else:
            user.state = UserState.GROUNDED
            status = HTTPStatus.FORBIDDEN
            status_message = "Please identify!"

        db.session.add(user)
        db.session.commit()
        break

    return jsonify(
        {
            "token": token,
            "status_message": status_message,
            "status_code": status.value,
            "status_description": status.description
        }
    )


@app.route('/message', methods=['POST'])
def receive_message():
    message_type = request.json.get('message_type')
    token = request.json.get('token')
    message = request.json.get('message')
    current_ip = request.remote_addr

    status_message = ""
    status: HTTPStatus = HTTPStatus.OK

    while True:
        if message_type is None or message_type != "MESSAGE":
            status = HTTPStatus.BAD_REQUEST
            status_message = "Invalid or missing 'message_type'"
            break

        if token is None:
            status = HTTPStatus.BAD_REQUEST
            status_message = "Missing 'token'"
            break

        if message is None:
            status = HTTPStatus.BAD_REQUEST
            status_message = "Missing 'message'"
            break

        user: User = User.verify_auth_token(token=token)
        if not user:
            status = HTTPStatus.UNAUTHORIZED
            status_message = "Token Expired. Please identify"
            break

        if user.gate_keeper(current_ip, UserState.AUTHENTICATED):
            if message == "" or message == "logout":
                message = "logout"
                user.state = UserState.GROUNDED
                status = HTTPStatus.ACCEPTED
                status_message = "Empty or logout Message Received from {}".format(user.username)
            else:
                status = HTTPStatus.CREATED
                status_message = "Message Received from {}".format(user.username)
            write_to_file(username=user.username, timestamp=str(time()), message=message)
        else:
            user.state = UserState.GROUNDED
            status = HTTPStatus.FORBIDDEN
            status_message = "Please identify!"

        db.session.add(user)
        db.session.commit()
        break

    return jsonify(
        {
            "status_message": status_message,
            "status_code": status.value,
            "status_description": status.description
        }
    )


if __name__ == "__main__":
    if len(argv) != 2:
        print("Usage: python server.py <port>")
        exit()
    if not exists('db.sqlite'):
        db.create_all()
    portStr = argv[1]
    port = 6174
    if portStr.isnumeric():
        port = int(portStr)
    else:
        print("Port is not numeric. Running on default port 6174")
    app.run(host="0.0.0.0", port=port, debug=True)
