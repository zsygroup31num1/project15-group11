from random import randint
import math
import binascii
from sm3 import G_hash


def modinv(a, m):
    x1, x2, x3 = 1, 0, a
    y1, y2, y3 = 0, 1, m
    while y3 != 0:
        q = x3//y3
        t1, t2, t3 = x1-q*y1, x2-q*y2, x3-q*y3
        x1, x2, x3 = y1, y2, y3
        y1, y2, y3 = t1, t2, t3
    return x1 % m


def addition(x1, y1, x2, y2, a, p):
    if x1 == x2 and y1 == p-y2:
        return False
    if x1 != x2:
        lamda = ((y2-y1)*modinv(x2-x1, p)) % p
    else:
        lamda = (((3*x1*x1+a) % p)*modinv(2*y1, p)) % p
    x3 = (lamda*lamda-x1-x2) % p
    y3 = (lamda*(x1-x3)-y1) % p
    return x3, y3


def mutipoint(x, y, k, a, p):
    k = bin(k)[2:]
    qx, qy = x, y
    for i in range(1, len(k)):
        qx, qy = addition(qx, qy, qx, qy, a, p)
        if k[i] == '1':
            qx, qy = addition(qx, qy, x, y, a, p)
    return qx, qy


def kdf(z, klen):
    ct = 1
    k = ''
    for _ in range(math.ceil(klen/256)):
        k = k+G_hash(hex(int(z+'{:032b}'.format(ct), 2))[2:])
        ct = ct+1
    k = '0'*((256-(len(bin(int(k, 16))[2:]) % 256)) % 256)+bin(int(k, 16))[2:]
    return k[:klen]


# parameters
p = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
gx = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
gy = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
zz = '63E4C6D3B23B0C849CF85841484BFE48F61D59A5B16BA06E6E12D1DA27C5249A'
# 待加密的消息M：encryption standard
# 消息M的16进制表示：656E63 72797074 696F6E20 7374616E 64617264
'''
dB=0x1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0
xB=0x435B39CCA8F3B508C1488AFC67BE491A0F7BA07E581A0E4849A5CF70628A7E0A
yB=0x75DDBA78F15FEECB4C7895E2C1CDF5FE01DEBB2CDBADF45399CCF77BBA076A42
'''
dB = randint(1, n-1)
xB, yB = mutipoint(gx, gy, dB, a, p)


def encrypt(m: str, d1, d2):
    plen = len(hex(p)[2:])
    m = '0'*((4-(len(bin(int(m.encode().hex(), 16))
             [2:]) % 4)) % 4)+bin(int(m.encode().hex(), 16))[2:]
    klen = len(m)
    p1x, p1y = mutipoint(gx, gy, int(1/d1), a, p)
    p2x, p2y = mutipoint(gx, gy, int(1/(d1*d2)-1), a, p)
    m1 = zz+m
    e = G_hash(m1)
    k1 = randint(1, n)
    Q1x, Q1y = mutipoint(gx, gy, k1, a, p)
    k2 = randint(1, n)
    Q2x, Q2y = mutipoint(gx, gy, k2, a, p)
    k3 = randint(1, n)
    x1, y1 = mutipoint(gx, gy, k3*k1+k2, a, p)
    r = x1+int(e,16) % n
    s2 = d2*k3 % n
    s3 = d2*(r+k2) % n
    s = (d1*k1)*s2+d1*s3-r % n
    print('r=',r,'s=',s)
    miwen = math.gcd(r, s)
    return miwen




if __name__ == '__main__':
    d1 = randint(1, n)
    d2 = randint(1, n)
    print(encrypt('hello', d1, d2))