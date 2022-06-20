from faker import Faker
from hashlib import sha256
import requests
from commands import sign, encode_bytes, user_url, login_screen, private_key_file

faker = Faker(['en_NZ'])

session_id = login_screen()

# Make fake users
for i in range(30):
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
