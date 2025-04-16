# I've hidden some data using XOR with a single byte, but that byte is a secret. Don't forget to decode from hex first.
import sys 

encoded = bytes.fromhex("73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d")

def decode(s):
    return ''.join([chr(s ^ a) for a in encoded])

for i in range(0, 127):
    if "crypto" in decode(i):
        print(decode(i))
        
        
# input_str = bytes.fromhex('73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d')
# key = input_str[0] ^ ord('c')
# print(''.join(chr(c ^ key) for c in input_str))