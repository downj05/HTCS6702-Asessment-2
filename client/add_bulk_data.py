from faker import Faker
import csv
from hashlib import sha256
import requests
from commands import *

faker = Faker(['en_NZ'])

session_id = login_screen()


# Remove Unicode:
def strip_unicode(input: str):
    string = input.encode("ascii", "ignore")
    return string.decode('ascii')


# Make fake users
def fake_user(amount):
    for i in range(amount):
        firstname = faker.first_name()
        lastname = faker.last_name()
        email = f'{firstname[0].lower()}{lastname.lower()}@{faker.free_email_domain()}'
        city = faker.city()

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
        response = requests.post(user_url + '/add', json=user_json)
        print("Got response from server")
        rjson = response.json()
        if 'SUCCESS' in rjson['type']:
            print(rjson['message'])
        else:
            print(f"Error! {rjson['message']}")


# Make fake services
def fake_service(amount):
    with open('dice_com-job_us_sample.csv', 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        data = list(reader)[1:]
        for r in data:
            if len(r[1]) > 32:
                continue
            elif len(r[0]) > 128:
                continue
            else:
                name = strip_unicode(r[1])
                description = strip_unicode(r[0])
                print(f"adding {name}, {description[:10]}...")
                combined = f'{name}{description}'
                fingerprint = sha256(combined.encode('ascii'))
                signature = encode_bytes(sign(fingerprint.digest(), private_key_file))
                service_json = {'session_id': session_id, 'name': name, 'description': description,
                                'signature': signature}
                response = requests.post(service_url + '/add', json=service_json)
                rjson = response.json()
                if 'SUCCESS' in rjson['type']:
                    print(rjson['message'])
                else:
                    print(f"Error! {rjson['message']}")


fake_service(300)


