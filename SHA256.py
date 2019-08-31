from collections import deque

primes = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
          0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
          0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
          0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
          0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
          0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
          0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
          0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]


def sum0(bits):
    seq = deque(bits)
    x = int(rotate(seq.copy(), 2), 2) ^ int(rotate(seq.copy(), 13), 2) ^ int(rotate(seq.copy(), 22), 2)
    return x


def sum1(bits):
    seq = deque(bits)
    return int(rotate(seq.copy(), 6), 2) ^ int(rotate(seq.copy(), 11), 2) ^ int(rotate(seq.copy(), 25), 2)


def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def ch(x, y, z):
    return (x & y) ^ (~x & z)


def add_end(string):
    return string + "1"


def rotate(sequence, n):
    sequence.rotate(n)
    return ''.join(sequence)


def add_padding(string):
    return add_end(string) + "0" * (512 - len(add_end(string)) - len(format(len(string), '032b'))) + ''.join(format(len(string), '032b'))


def sigma0(bits):
    seq = deque(bits)
    return int(rotate(seq.copy(), 7), 2) ^ int(rotate(seq.copy(), 18), 2) ^ int(bits, 2) >> 3


def sigma1(bits):
    seq = deque(bits)
    return int(rotate(seq.copy(), 17), 2) ^ int(rotate(seq.copy(), 19), 2) ^ int(bits, 2) >> 10


def SHA256(string):
    binSt = add_padding(''.join(format(ord(x), '08b') for x in string))
    split_binSt = []
    for i in range(32, 513, 32):
        split_binSt.append(binSt[i - 32:i])
    h0, h1, h2, h3, h4, h5, h6, h7 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7


    for i in range(64):
        if i > 15:
            split_binSt.append(format((sigma1(split_binSt[i - 2]) + sigma0(split_binSt[i - 15]) + int(split_binSt[i - 7],2) + int(split_binSt[i - 16], 2)) % 2 ** 32, '032b'))
        T1 = (h + sum1(format(e, '032b')) + ch(e, f, g) + primes[i] + int(split_binSt[i], 2)) % 2 ** 32
        T2 = (sum0(format(a, '032b')) + maj(a, b, c)) % 2 ** 32
        h = g
        g = f
        f = e
        e = (d + T1) % 2 ** 32
        d = c
        c = b
        b = a
        a = (T1 + T2) % 2 ** 32
    h0 = (h0 + a) % 2 ** 32
    h1 = (h1 + b) % 2 ** 32
    h2 = (h2 + c) % 2 ** 32
    h3 = (h3 + d) % 2 ** 32
    h4 = (h4 + e) % 2 ** 32
    h5 = (h5 + f) % 2 ** 32
    h6 = (h6 + g) % 2 ** 32
    h7 = (h7 + h) % 2 ** 32

    return (hex(h0), hex(h1), hex(h2), hex(h3), hex(h4), hex(h5), hex(h6), hex(h7))

print(SHA256(input()))