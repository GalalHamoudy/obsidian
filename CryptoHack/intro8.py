import sys

cipher_txt = bytes.fromhex("0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104")
partial_flag = 'crypto{1'
key = ''.join([chr(cipher_txt[i] ^ ord(partial_flag[i])) for i in range(len(partial_flag))])

output = b''
for i in range(len(cipher_txt)):
    # XOR the cipher text bit and key bit
    # CipherText:  14      11     33 63 ...
    #              ⊕       ⊕       ⊕  ⊕
    #        Key: 109     121     88 79 ...
    #       Flag:  99 (c) 114 (r)
    output += bytes([cipher_txt[i] ^ ord(key[i % len(key)])])

print(output)