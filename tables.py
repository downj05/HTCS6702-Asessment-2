import base64
import sqlite3
from hashlib import sha256
import rsa

database = 'main.db'
try:
    conn = sqlite3.connect(database, check_same_thread=False)
except Exception as e:
    print(f"Error connecting to database: {e}")


def execute(sql_cmd: str, values: tuple):
    """
    Takes an SQL command, and any values, then executes it
    using a cursor with the database connection.
    :param sql_cmd:
    :param values:
    :return:
    """
    cur = conn.cursor()
    cur.execute(sql_cmd, values)
    conn.commit()
    cur.close()


def get_all_rows(table: str):
    """
    Takes in a table name, and fetches every row in it.
    Returns a list of tuples with the rows information.
    :param table:
    :return: row_list
    """
    sql_command = f'''SELECT * FROM {table}'''

    cur = conn.cursor()
    cur.execute(sql_command)
    return cur.fetchall()


def get_some_rows(table: str, amount: int):
    """
    Fetches n amount of rows from a specified table.
    :param table:
    :param amount:
    :return: row_list
    """
    sql_command = f'''SELECT * FROM {table}'''
    cur = conn.cursor()
    cur.execute(sql_command)
    rows = cur.fetchmany(amount)
    print(f"Got {len(rows)} from database")
    return rows


def verify_signature(message: bytes, signature: bytes, signer_id: int):
    """
    Takes a message, signature and the id of the person who signed it.
    Dereferences the signer_id to retrive public key from auth table.
    Uses public key to validate signature.
    :param message:
    :param signature:
    :param signer_id:
    :return:
    """
    print("Get public key from database")
    sql_cmd = '''SELECT public_key FROM auth WHERE id = ?'''
    cur = conn.cursor()
    cur.execute(sql_cmd, (signer_id,))
    print("Decode public key")
    public_key = cur.fetchone()[0].encode('ascii').decode('unicode_escape')
    public_key = rsa.PublicKey.load_pkcs1(public_key)
    print("RSA verify function")
    try:
        if rsa.verify(message, signature, public_key):
            print("RSA verification success")
            return True
        else:
            print("RSA verification failed")
            return False
    except Exception as e:
        print(f"Error! {e}")


def decode_bytes(base64_string: str):
    """
    Decode a base64 encoded string into bytes.
    :param base64_string:
    :return bytes:
    """
    return base64.b64decode(base64_string.encode('ascii'))


class User:
    """
    User class, has its first name, last name, email and city.
    :param row_tuple:
    """
    def __init__(self, row_tuple=(None, None, None, None, None)):
        self.id = row_tuple[0]
        self.firstName = row_tuple[1]
        self.lastName = row_tuple[2]
        self.email = row_tuple[3]
        self.city = row_tuple[4]

    @property
    def fingerprint(self):
        """
        Returns a SHA-256 hash of the users data
        appended together, for the purpose of validating
        signatures.
        :returns: object_bytes
        """
        row = f'{self.firstName}{self.lastName}{self.email}{self.city}'
        print(f"Make combined {row}")
        fingerprint = sha256(row.encode('ascii'))
        print(f"Make fingerprint {fingerprint.hexdigest()[0:6]}...")
        return fingerprint.digest()

    def add(self, signature: bytes, signer: int):
        """
        Adds the current object to the database.
        The signature is added alongside as well as
        the signers ID.
        :param signature:
        :param signer:
        """
        sql_cmd = '''INSERT INTO user(firstName, lastName, email, city, signature, signer) VALUES(?,?,?,?,?,?)'''
        values = (self.firstName, self.lastName, self.email, self.city, signature, signer)
        execute(sql_cmd, values)

    def update(self, signature: bytes, signer: int):
        """
        Update the current object to match the row
        in the database with the same ID. Requires
        a signature and a signer for integrity.
        :param signature:
        :param signer:
        :return:
        """
        sql_cmd = '''UPDATE user SET firstName = ?, lastName = ?, email = ?, city = ?, signature = ?, signer = ?
        WHERE userID = ?'''
        values = (self.firstName, self.lastName, self.email, self.city, signature, signer)
        execute(sql_cmd, values)

    def delete(self):
        """
        Delete the current object from
        the database so long as it has the
        same ID
        :return:
        """
        sql_cmd = '''DELETE FROM user WHERE userID = ?'''
        values = (self.id,)
        execute(sql_cmd, values)



class Service:
    def __init__(self):
        pass

if __name__ == '__main__':
    get_some_rows('users', 3)
