import sys

# import math 
# print(math.gcd(66528,52920))


def euclid_gcd(x, y):
    if x < y:
        return euclid_gcd(y, x)

    while y != 0:
        (x, y) = (y, x % y)

    print("\n[+] GCD: {}".format(x))
    return x


a = 66528
b = 52920

euclid_gcd(a, b)

