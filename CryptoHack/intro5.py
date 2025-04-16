# We can XOR integers by first converting the integer from decimal to binary. We can XOR strings by first converting each character to the integer representing the Unicode character.
# The Python pwntools library has a convenient xor() function that can XOR together data of different types and lengths. But first, you may want to implement your own function to solve this.

import sys 

str = "label"
num_to_ascii = []

for x in str:
    ascii_to_num = ord(x) ^ 13
    num_to_ascii.append(chr(ascii_to_num))
    
flag = ''.join(num_to_ascii)
print(flag)

