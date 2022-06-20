import requests
from hashlib import sha256
import base64
import rsa
import os

server_url = 'http://localhost:5000'

private_key_file = 'client_private.pem'
session_file = 'client.session'

login_url = server_url+'/login'
info_url = server_url+'/info'
list_url = server_url+'/list'
user_url = server_url+'/user'

session_id = None


def add_service(session_id):
    """Ask for service information and a confirmation. Takes
    a fingerprint of the service data, signs it with our private
    key. Send the service data """

def add_user(session_id):
    """Ask for user information and a confirmation. Takes a
    fingerprint of the user data, signs it with our
    private key. Send the user data and signature to the server
    which validate the signature and add it to the database."""
    print("Add a user.")
    firstname = input("First Name:")
    lastname = input("Last Name:")
    email = input("Email Address:")
    city = input("City:")
    # Confirmation loop
    while True:
        confirm = input(f"Are you sure you want to add {firstname} {lastname}? (y/n):")
        if confirm.lower() in ['n', 'no']:
            print("Cancelled user creation.")
            return
        elif confirm.lower() in ['y', 'yes']:
            print("Adding user...")
            break # Leave loop
    combined = f'{firstname}{lastname}{email}{city}'
    print(f"Make combined {combined}")
    fingerprint = sha256(combined.encode('ascii'))
    print(f"Generated fingerprint {fingerprint.hexdigest()[0:6]}...")
    signature = sign(fingerprint.digest(), private_key_file)
    print(f"Made signature {signature.hex()[0:6]}...")
    signature = encode_bytes(signature)
    print(f"Encoded signature into base64 {signature[0:6]}...")
    user_json = {'session_id': session_id, 'firstName': firstname, 'lastName': lastname,
                 'email': email, 'city': city, 'signature': signature}
    print("Send data to server...")
    response = requests.post(user_url+'/add', json=user_json)
    print("Got response from server")
    rjson = response.json()
    if 'SUCCESS' in rjson['type']:
        print(rjson['message'])
    else:
        print(f"Error! {rjson['message']}")


def list_table(session_id, table: str, amount: int):
    """Request n amount of rows from specified table.
    Prints them out."""
    response = requests.get(url=list_url+'/'+table, json={'session_id': session_id, "amount": amount})
    print("List command got code", response.status_code)

    rjson = response.json()
    if 'ERROR' in rjson['type']:
        print("List Error!", rjson['message'])
        return
    elif 'SUCCESS' in rjson['type']:
        if table.lower() == 'user':
            print("ID".ljust(8) + '| First Name'.ljust(40) + '| Last Name'.ljust(40) + '| Email'.ljust(32) + '| City')
            for r in rjson['message']:
                print(f"{r[0]}".ljust(8) + f'| {r[1]}'.ljust(40) + f'| {r[2]}'.ljust(40) + f'| {r[3]}'.ljust(32) + f'| {r[4]}')


def sign(data: bytes, private_key_path: str):
    """Every time a user edits something in the database, a signature of that
    edited row is added to the end. This signature also has a signer part,
    which is the clients' user id. This is used in conjunction with the users
    public key to verify that only an authorized user of the server could
    have edited that row."""
    with open(private_key_path, 'rb') as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    signature = rsa.sign(data, private_key, 'SHA-256')
    return signature


def encode_bytes(byte_string: bytes):
    """
    Encode bytes into base64 for sending as a JSON object over HTTP
    :param byte_string:
    :return string:
    """
    return base64.b64encode(byte_string).decode('ascii')


def login_screen():
    """
    If there is a previous session file, load it and try authenticate with it.
    If the session is invalid or a session file does not exist, force the
    user to login with their credentials and OTP code.
    :return session_key:
    """
    # Log in loop
    while True:
        print("Welcome to the Phone-Me administration client!")
        # Check if we have a session file
        if os.path.exists(session_file):
            print(f"Logging in from previous session with {session_file}...")
            with open(session_file, 'r') as f:
                session_key = f.read()
                json_payload = {
                    "session_id": session_key
                }
        else:
            # Log into server
            print("Please enter your credentials to login to the server.")
            username = input("Username: ")
            password = input("Password: ")
            otp_code = input("One Time Code: ")

            json_payload = {
                "session_id": None,
                "username": username,
                "password": password,
                "otp": otp_code
            }

        # Send request
        try:
            response = requests.post(url=login_url,json=json_payload)
        except ConnectionError:
            print("Cannot connect to server!")
            return None

        json_response = response.json()
        if 'ERROR' in json_response['type']:
            print(json_response['message'])
            if json_response['type'] == 'ERROR_SESSION_EXPIRED':  # Session has expired
                print("Deleting old session...")
                os.remove(session_file)  # Delete old session to avoid session loop

        elif json_response['type'] == 'SESSION_ASSIGNMENT':
            session_key = json_response['message']
            print(f"Login successful, received session key {session_key[0:6]}...")
            with open(session_file, 'w') as f:
                f.write(session_key)  # Save session key
            break  # Leave login loop

        elif json_response['type'] == 'SESSION_LOGIN_SUCCESS':
            print(f"Logged in with session successfully.")
            break  # Leave login loop

    return session_key


def info(session_key):
    response = requests.get(info_url, json={"session_id": session_key})
    print(response.json()['message']) # Print server info screen


def help():
    help_message = """Commands:
    list <table> <amount> - Lists <amount> rows from <table>.
    add <table> - Opens the object creation screen for the specified object.
    update <table>  - Open the object update screen for the specified object.
    delete <table> - Opens the object deletion screen for the specified object.
    info - Shows some info about the server.
    help - Shows this message
    Tables:
    user - The end users of Phone-Me.
    service - Services that the end users can subscribe to.
    subscription - Represents a subscription between a user and a service."""
    print(help_message)


if __name__ == '__main__':
    public_key = rsa.PublicKey.load_pkcs1('-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAwevFxG1Ga3k5/9PdVu4+Oxw6cAr3kFj5uJo2RbnSQNjnK3M2Uhm6\nSXeIa791cVSTvuqdaHF5PNs7sKC4ZiDPVTCEOFBmPpGQU8cQ7rf4KRh6soxN8bth\nsMdLg6tnrvbbzkdZl4LgTjj5NxxJbefL25wi4nGQLVryVaqWj39v7EAI3ca66FH9\nKUgjw9luCiqZEmEtIk9uVEPk4wFbDOELCtG/OwVfQPI7cOv7YYBebQFjzk4RC167\nAI5XsKcebz7UDVUIo2UOJMpY/nrx6nuQh8hFTnl+mrj3OZXlKJ37jN0/1FXQ0PFN\nQb1WH/dghiTWCP1Y7nfPqC5EeyzJkxb8WwIDAQAB\n-----END RSA PUBLIC KEY-----\n')
    with open(private_key_file, 'rb') as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    message = b'hello world!'
    sig = rsa.sign(message, private_key, 'SHA-256')
    print("message hash", sha256(message).hexdigest())
    print("signature hash", sha256(base64.b64encode(sig)).hexdigest())
    print("public key hash", sha256(public_key.save_pkcs1()).hexdigest())
    verification = rsa.verify(message, sig, public_key)

    sig = base64.b64encode(sig).decode('ascii')
    print(sig)

