import sqlite3
import OTP
import bcrypt
import rsa
from secrets import token_hex
import time
database = 'main.db'
session_expiry = 3600  # How long a session id is valid for in seconds
session_id_length = 64

try:
    conn = sqlite3.connect(database, check_same_thread=False)
except Exception as e:
    print(f"Error connecting to database: {e}")


invalid_session_message = {'type': 'ERROR',
                           'message': 'Your session is invalid or expired. Please get a new one by logging in again.'}


def get_id_from_session(session_id: str):
    """
    Get the id of a user based on their
    session id
    :param session_id:
    :return: user_id
    """
    sql_cmd = '''SELECT id FROM AUTH WHERE session_id = ?'''
    cur = conn.cursor()
    cur.execute(sql_cmd, (session_id,))
    row = cur.fetchone()
    if row is None:
        return False
    else:
        return row[0]


def get_session_expiry(session_id):
    """
    Get the expiry of a session id
    :param session_id:
    :return: timestamp
    """
    sql_cmd = '''SELECT session_expiry FROM AUTH WHERE session_id = ?'''
    cur = conn.cursor()
    cur.execute(sql_cmd, (session_id,))
    row = cur.fetchone()
    if row is None:
        return False
    else:
        return row[0]


def check_session_id(session_id):
    sql_cmd = '''SELECT session_expiry FROM AUTH WHERE session_id = ?'''
    cur = conn.cursor()
    cur.execute(sql_cmd, (session_id,))
    row = cur.fetchone()
    if row is None or row[0] < time.time():
        return False
    else:
        return True


def create_session_id(username):
    '''
    Create a session id of configured length, create an expiry date of configured length,
    add to the users row in the database,
    :param username:
    :return: None
    '''
    sql_cmd = '''UPDATE auth SET session_id = ?, session_expiry = ? WHERE username = ?'''
    cur = conn.cursor()
    session_id = token_hex(session_id_length)
    cur.execute(sql_cmd, (session_id, int(time.time())+session_expiry, username.lower()))
    conn.commit()
    cur.close()
    return session_id


def check_credentials(username, password):
    sql_cmd = '''SELECT password FROM AUTH WHERE username = ?'''
    cur = conn.cursor()
    cur.execute(sql_cmd, (username.lower(),))
    row = cur.fetchone()
    if row is None:
        return False
    hashed = row[0]
    if bcrypt.checkpw(password.encode('ascii'), hashed):
        return True
    else:
        return False


def check_otp(username, code):
    sql_cmd = '''SELECT otp FROM AUTH WHERE username = ?'''
    cur = conn.cursor()
    cur.execute(sql_cmd, (username.lower(),))
    row = cur.fetchone()
    if row is None:
        return False
    otp_secret = row[0]
    otp_instance = OTP.Otp(otp_secret)
    generated_code = otp_instance.get_otp()
    print(f"Comparing {generated_code} to {code}")
    if int(generated_code) == int(code):  # To avoid casting str versions of code to  int every time called
        return True
    else:
        return False


def register(username, password, public_key):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('ascii'), salt)
    otp = OTP.create_otp()
    sql_cmd = '''INSERT INTO AUTH(username, password, otp, public_key) VALUES (?, ?, ?, ?)'''
    cur = conn.cursor()
    cur.execute(sql_cmd, (username.lower(), hashed, otp, public_key))
    conn.commit()
    cur.close()


def user_exists(username):
    sql_cmd = '''SELECT username FROM auth WHERE username = ?'''
    cur = conn.cursor()
    cur.execute(sql_cmd, (username.lower(),))
    row = cur.fetchone()
    if row is None:
        return False
    else:
        return True


if __name__ == '__main__':
    print(type(create_session_id('admin')))
