import time
import base64
from random import randint
import json
from hashlib import sha256

otp_secret_range_a = 2**256
otp_secret_range_b = 2**257 # the secret is between 2^64 and 2^65. eliminates any attempt at brute forcing the otp secret
mod = 10 # how many seconds a new code is generated

def create_otp():
    '''
    creates a sharable secret that lets two parties generate OTP codes
    :return: sharable_secret
    '''
    random_number = randint(otp_secret_range_a, otp_secret_range_b)
    secret = sha256((random_number).to_bytes(64, byteorder='little')).hexdigest()
    secret_json = {
        'lifetime': mod,
        'secret': secret
    }
    return base64.b64encode(json.dumps(secret_json).encode('ascii')).decode('ascii')


class Otp:
    '''
    :argument: secret
    load in an otp secret, generate a new one time code every mod seconds
    '''
    def __init__(self, secret):
        secret_json = json.loads(base64.b64decode(secret.encode('ascii')).decode('ascii'))
        self.lifetime = secret_json['lifetime']
        self.secret = secret_json['secret']

    def otp_from_timestamp(self, current_time):
        return int.from_bytes(sha256(f"{current_time}{self.secret}".encode('ascii')).digest()[0:2], byteorder="little")

    def get_otp(self):
        current_time = int(time.time())
        if current_time % self.lifetime == 0:
            return self.otp_from_timestamp(current_time)
        else:
            while True: # Decrement time by 1 second until mod matches, then generate otp
                current_time -= 1
                if current_time % self.lifetime == 0:
                    break
            return self.otp_from_timestamp(current_time)

    def get_remaining_time(self):
        return self.lifetime - (int(time.time()) % self.lifetime)