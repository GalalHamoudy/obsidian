import sys 

from binascii import unhexlify

with open("a.png", mode='rb') as fl:
    lemur = fl.read()
    

with open("aa.png", mode='rb') as ff:
    flag = ff.read()

d = b''
for b1, b2 in zip(lemur, flag):
    d += bytes([b1^b2])

with open("new.png", mode='wb') as fn:
    fn.write(d)
    
    
""""

performing a visual XOR between the RGB bytes of the two images - not an XOR of all the data bytes of the files.

ImageMagick can do it, although it's a bit convoluted. One way is:

convert img1 img2 -fx "(((255*u)&(255*(1-v)))|((255*(1-u))&(255*v)))/255" img_out
(img1,img2,img_out are the two input and single output file names respectively).

"""