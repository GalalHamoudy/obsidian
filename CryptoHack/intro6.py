#  Before you XOR objects, be sure to decode from hex to bytes.
# KEY1 = a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313
# KEY2 ^ KEY1 = 37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e
# KEY2 ^ KEY3 = c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1
# FLAG ^ KEY1 ^ KEY3 ^ KEY2 = 04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf

import sys
import base64
from Crypto.Util.number import *

KEY1_hex = "a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313"
KEY2_xor_KEY1_hex = "37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e"
KEY2_xor_KEY3_hex = "c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1"
FLAG_xor_KEY1_xor_KEY3_xor_KEY2_hex = "04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf"

# Convert hexadecimal strings to integers
def hex_to_int(hex_str):
    return int(hex_str, 16)

# Convert integer to hexadecimal string
def int_to_hex(num):
    return hex(num)[2:]

# Convert hexadecimal strings to integers
KEY1 = hex_to_int(KEY1_hex)
KEY2_xor_KEY1 = hex_to_int(KEY2_xor_KEY1_hex)
KEY2_xor_KEY3 = hex_to_int(KEY2_xor_KEY3_hex)
FLAG_xor_KEY1_xor_KEY3_xor_KEY2 = hex_to_int(FLAG_xor_KEY1_xor_KEY3_xor_KEY2_hex)

# Calculate KEY2
KEY2 = KEY2_xor_KEY1 ^ KEY1

# Calculate KEY3
KEY3 = KEY2_xor_KEY3 ^ KEY2 


# Calculate FLAG
FLAG = FLAG_xor_KEY1_xor_KEY3_xor_KEY2 ^ KEY1 ^ KEY3 ^ KEY2



#  ----------------------------------

KEY1_hex = "a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313"
KEY2_hex = "911404e13f94884eabbec925851240a52fa381ddb79700dd6d0d"
KEY3_hex = "504053b757eafd3d709d6339b140e03d98b9fe62b84add0332cc"
FLAG_hex = "63727970746f7b7830725f69355f61737330633161743176337d"


# testo = hex_to_int(KEY1_hex) ^ hex_to_int(KEY2_hex) ^ hex_to_int(KEY3_hex) ^ hex_to_int(FLAG_hex)
# print(int_to_hex(testo))

print(bytes.fromhex(FLAG_hex))
