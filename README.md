# Flask Message Gatherer

This repository has a simple, low-level Client and Server applications to send and receive messages, respectively. The purpose of this app is to gather all the messages sent from the any endpoint running the client and dump it to the server node.

## Primary requirements

- The client and server must support three message types

  - Identification Message - client must provide an identifier
  - Authentication Message - client must provide a password
  - Data Message - client provides one or more data messages

- The messages must be received in order (i.e. the server will not accept a data message without first receiving an Identification and Authentication message)

- Platform agnostic applications

## Components

- REST Server: Handles incoming three different message types as POST requests
- Relational DB: Handles user sessions, password hashing and JWT token generation
- Client CLI: Used to send the messages to the server
- File System: Used to dump the data messages to a file

## High-level Process flow

- Server is started on a configured port
- It initializes a [database](#Database) which helps us handling the user sessions
- Client sends in a [request](#Requests)
- Based on the current [state](#States) of the user the [message](#Messages) is processed
- Responses are sent back to the client

## Use case diagram

![Use case diagram](/flask-app/diagrams/use_case.drawio.png)

## Messages

The events that gets triggered by the following messages are listed below

- Identification message
  - Verifies the presence of the user in the database
  - Adds the user to the database if not found
- Authentication message
  - Verifies the password hash of the user with the one in the database
  - Creates a password hash with user name as the salt and stores it in the database
  - Generates a JWT token with a timed expiry for sending data messages
- Data message
  - Authenticates the user with the JWT token
  - Writes the data message into the file

## Database

The schema of the database implemented with the help of flask_sqlalchemy module

- id: Int
- username: String(32)
- password_hash: String(128)
- state: Int
- last_endpoint: String(16)

## Requests

Message are passed in as a form of POST request. The sample request structure of the messages are given below.

### Identify message request

```JSON
{
    "message_type": "IDENTIFY",
    "username": "dale"
}
```

### Authenticate message request

```JSON
{
    "message_type": "AUTHENTICATE",
    "username": "dale",
    "password": "pass"
}
```

### Data message request

```JSON
{
    "message_type": "MESSAGE",
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwiZXhwIjoxNjQ5NzIzNTgwLjUxMTk0OX0.-7wwQAjYXzc6fjPEIa0nTqZAnP3LD2h_muUx2SRWI2A",
    "message": "Hail Dale!"
}
```

Postman requests for testing the server is [here](/flask-app/postman-tests/)

## States

States help us in streamling the user flow. It has been considered as part of the user session. Following are the states being used and their transition is depicted below.

- Grounded
  - All users will start here
  - User is allowed to be identified
- Identified
  - The user has got identified and has an entry in the database
  - User is allowed to be authenticated
- Authenticated
  - Verified the password of user and generated a JWT access token
  - User is allowed to send data messages

### State Diagram

![State transition diagram](flask-app/diagrams/states.drawio.png)

## Low-level Process sequence

![Sequence diagram](flask-app/diagrams/sequence.drawio.png)

## Language and Modules

**Language:**

- Python

**Modules:**

- **Server**: [requirements.txt](flask-app/server/requirements.txt)
- **client**: [requirements.txt](flask-app/client/requirements.txt)

## Usage

### Server

```bash
cd flask-app/server
pip install -r requirements.txt
python server.py <port>
```

### Client

```bash
cd flask-app/client
pip install -r requirements.txt
python client.py <server:port>
```

## Possible Vulnerabilities and fixes

- Password is sent as part of the POST request. Unless the connection is SSL secured, it can be exposed
- Password hash rather than password is being stored in the database
- JWT tokens give us more control over the resource being provided
- File lock is implemented to overcome race-conditions between writes

## Takeaway

- Flask is more granular compared to Django web-framework
- JWT tokens is a new learning
- Handling user sessions are little convoluted
- Identification and Authentication could be a single message
- PyJWT encoding sometimes returns bytes and not direct strings
