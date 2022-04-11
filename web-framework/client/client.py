from enum import IntEnum
from http import HTTPStatus
from json import dumps
from requests import request
from sys import argv

TOKENS: dict = {}

class USER_OPTIONS(IntEnum):
    IDENTIFY = 1
    AUTHENTICATE = 2
    MESSAGE = 3
    CHANGE_NAME = 4
    HELP = 5
    EXIT = 6

def print_help(server: str):
    print("Connected to the Server:", server)
    print("Options:")
    print("\t1. Identify")
    print("\t2. Authenticate")
    print("\t3. Send Message to Server")
    print("\t4. Switch User")
    print("\t5. View Help")
    print("\t6. Exit")


def identify(server: str, username: str):
    endpoint: str = server + "/identify"

    payload = dumps({
        "message_type": "IDENTIFY",
        "username": username
    })
    headers = {
        "Content-Type": "application/json"
    }

    response = request("POST", endpoint, headers=headers, data=payload)

    print(response.json()['status_message'])


def authenticate(server: str, username: str):
    endpoint: str = server + "/authenticate"

    password = input(">>> Password: ")

    payload = dumps({
        "message_type": "AUTHENTICATE",
        "username": username,
        "password": password
    })
    headers = {
        "Content-Type": "application/json"
    }

    response = request("POST", endpoint, headers=headers, data=payload)

    token = response.json()['token']
    if token != "":
        TOKENS[username] = response.json()['token']

    print(response.json()['status_message'])


def send_message(server: str, username: str):
    endpoint: str = server + "/message"

    if username not in TOKENS.keys():
        print("Identify first!")
        return

    message = input(">>> Message: ")
    status: HTTPStatus.value = HTTPStatus.CREATED.value

    while message != "exit":
        payload = dumps({
            "message_type": "MESSAGE",
            "token": TOKENS[username],
            "message": message
        })
        headers = {
            "Content-Type": "application/json"
        }

        response = request("POST", endpoint, headers=headers, data=payload)

        print(response.json()['status_message'])

        if HTTPStatus.CREATED.value != int(response.json()['status_code']):
            break

        message = input(">>> Message: ")


def main(server: str):
    print_help(server=server)

    username = input(">>> Enter Username: ")

    optionStr = input(">>>" + " ({})".format(username) + " Enter Option [1-5]: ")
    if optionStr.isnumeric():
        option = int(optionStr)
    else:
        print("Option should be an integer. Please look at the help doc")
        option = 5
    
    while option < USER_OPTIONS.EXIT:
        if option == USER_OPTIONS.IDENTIFY:
            identify(server=server, username=username)
        elif option == USER_OPTIONS.AUTHENTICATE:
            authenticate(server=server, username=username)
        elif option == USER_OPTIONS.MESSAGE:
            send_message(server=server, username=username)
        elif option == USER_OPTIONS.CHANGE_NAME:
            username = input(">>> Enter Username: ")
        elif option == USER_OPTIONS.HELP:
            print_help(server=server)
        else:
            return

        optionStr = input(">>>" + " ({})".format(username) + " Enter Option [1-5]: ")
        if optionStr.isnumeric():
            option = int(optionStr)
        else:
            print("Option should be an integer. Please look at the help doc")
            option = 5


if __name__ == "__main__":
    if len(argv) != 2:
        print("Usage: python client.py <server address>:<port>")
        exit()
    main(server=argv[1])
