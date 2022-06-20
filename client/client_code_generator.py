import time
import OTP
otp_file = 'client_otp.otp'

with open(otp_file, 'r') as f:
    otp_instance = OTP.Otp(f.read())
while True:
    print(otp_instance.get_otp(), otp_instance.get_remaining_time())
    time.sleep(1)