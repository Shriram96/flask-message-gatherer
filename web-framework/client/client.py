from http import HTTPStatus
from json import dumps
from requests import request
from sys import argv

TOKENS: dict = {}


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

    TOKENS[username] = response.json()['token']
    print(response.json()['status_message'])


def authenticate(server: str, username: str):
    endpoint: str = server + "/authenticate"

    if username not in TOKENS.keys():
        print("Identify first!")
        return

    payload = dumps({
        "message_type": "AUTHENTICATE",
        "token": TOKENS[username]
    })
    headers = {
        "Content-Type": "application/json"
    }

    response = request("POST", endpoint, headers=headers, data=payload)

    print(response.json()['status_message'])


def send_message(server: str, username: str):
    endpoint: str = server + "/message"

    if username not in TOKENS.keys():
        print("Identify first!")

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

    option = int(input(">>>" + " ({})".format(username) + " Enter Option [1-5]: "))
    while option < 6:
        if option == 1:
            identify(server=server, username=username)
        elif option == 2:
            authenticate(server=server, username=username)
        elif option == 3:
            send_message(server=server, username=username)
        elif option == 4:
            username = input(">>> Enter Username: ")
        elif option == 5:
            print_help(server=server)
        else:
            return

        option = int(input(">>>" + " ({})".format(username) + " Enter Option [1-5]: "))


if __name__ == "__main__":
    if len(argv) != 2:
        print("Usage: python client.py <server address>:<port>")
        exit()
    main(server=argv[1])
