import random
from math import *
# =========================================================
# Joshua Lowe
# September 29, 2020
#
# Encrption and Decryption methods for Caesar,
# Vigenere and Merkle-Hellman Knapsack encryption systems.
# =========================================================


# Shift helper function
# Arguments: string, integer
# Returns: string
def shift(letter, offset):
    return chr((ord(letter) - ord('A') + offset) % 26 + ord('A'))


# Caesar Cipher
# Arguments: string, integer
# Returns: string
def encrypt_caesar(plaintext, offset):
    return ''.join([shift(letter, offset) if letter.isalpha()
                    else letter for letter in plaintext])


# Arguments: string, integer
# Returns: string
def decrypt_caesar(ciphertext, offset):
    return encrypt_caesar(ciphertext, -offset)


# Vigenere Cipher
# Arguments: string, string
# Returns: string
def encrypt_vigenere(plaintext, keyword):
    shifted = [shift(plaintext[i], ord(keyword[i % len(keyword)]) - ord('A'))
               for i in range(len(plaintext))]
    return ''.join(shifted)


# Arguments: string, string
# Returns: string
def decrypt_vigenere(ciphertext, keyword):
    shifted = [shift(ciphertext[i], ord('A') - ord(keyword[i % len(keyword)]))
               for i in range(len(ciphertext))]
    return ''.join(shifted)


# Merkle-Hellman Knapsack Cryptosystem
# Arguments: integer
# Returns: tuple (W, Q, R) -
#          W a length-n tuple of integers, Q and R both integers
def generate_private_key(n=8):
    W = super_inc(n)
    Q = get_next_super(W)
    R = gen_coprime(Q)
    return (W, Q, R)


# Super-increasing sequence helper function
# Arguments: 3 integers - length of sequence, lowest and highest start
# Returns: integer list
def super_inc(n, low=1, high=10):
    x = []
    for i in range(n - 1):
        if not x:
            x.append(random.randint(1, 10))
        x.append(get_next_super(x))
    return x


# Super-increasing number helper function
# Arguments: integer list
# Returns: integer
def get_next_super(x):
    return random.randint(sum(x) + 1, sum(x) * 2)


# Coprime pair helper function
# Arguments: integer
# Returns: integer
def gen_coprime(Q):
    R = Q
    while gcd(R, Q) != 1:
        R = random.randint(2, Q - 1)
    return R


# Arguments: tuple (W, Q, R) -
#            W a length-n tuple of integers, Q and R both integers
# Returns: tuple B - a length-n tuple of integers
def create_public_key(private_key):
    W = private_key[0]
    Q = private_key[1]
    R = private_key[2]
    return tuple([(R * elem) % Q for elem in W])


# Arguments: string, tuple B
# Returns: list of integers
def encrypt_mhkc(plaintext, public_key):
    return [encrypt_char(c, public_key) for c in plaintext]

# Arguments: string, tuple B
# Returns: integer
def encrypt_char(character, public_key):
    binary = "0" + bin(ord(character))[2:]
    binary = [int(i) for i in binary]
    ciphertext = sum([binary[i] * public_key[i] for i in range(len(binary))])
    return ciphertext


# Arguments: list of integers, private key (W, Q, R) with W a tuple.
# Returns: bytearray or str of plaintext
def decrypt_mhkc(ciphertext, private_key):
    return "".join(decrypt_char(char, private_key) for char in ciphertext)


# Arguments: integer, integer
# Returns: integer
def modular_inv(R, Q):
    S = 1
    while (R * S) % Q != 1:
        S += 1
    return S


# Arguments: string, tuple B
# Returns: string
def decrypt_char(character, private_key):
    S = modular_inv(private_key[2], private_key[1])
    W = private_key[0]
    c_prime = character * S % private_key[1]
    M = []
    for elem in W[::-1]:
        if elem <= c_prime:
            M.insert(0, 1)
            c_prime -= elem
        else:
            M.insert(0, 0)
    binary = "".join(str(i) for i in M)
    return chr(int(binary, 2))


def main():
    private = generate_private_key()
    public = create_public_key(private)
    encrypt = encrypt_mhkc("ABC", public)
    print(decrypt_mhkc(encrypt, private))
    # print(modular_inv(private[2], private[1]))

if __name__ == "__main__":
    main()
