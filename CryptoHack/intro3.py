import sys
import base64

hexStr = "72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf"

decoded_bytes = bytes.fromhex(hexStr) # decodes the hexadecimal string into bytes
base64_encoded = base64.b64encode(decoded_bytes) # encodes the decoded bytes into Base64 format
print(base64_encoded) 

# In Python, after importing the base64 module with import base64, you can use the base64.b64encode() function. Remember to decode the hex first as the challenge description states.

#------------------------------------------------
basee64 = "crypto/Base+64+Encoding+is+Web+Safe/"

base64_decoded = base64.b64decode(basee64) # decodes the Base64 encoded string back into bytes
hex_string = base64_decoded.hex()

print(hex_string)