import sys

hexString = "63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d"

print("Here is your flag:")
print(bytes.fromhex(hexString))

# In Python, the bytes.fromhex() function can be used to convert hex to bytes. The .hex() instance method can be called on byte strings to get the hex representation.

# --------------------------------------------

plaintext = "crypto{You_will_be_working_with_hex_strings_a_lot}"

print("Rev flag :")
hex_value = plaintext.encode().hex()
print(hex_value)


# encode() converts the string into bytes using the UTF-8 encoding (which is the default encoding in Python).
# hex() converts the bytes object into a hexadecimal string representation.