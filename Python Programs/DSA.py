import hashlib
import random
import math

# Function to generate a large prime number
def generate_large_prime(bits):
    while True:
        num = random.getrandbits(bits)
        if num > 1 and is_prime(num):
            return num

# Function to check if a number is prime
def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

# Function to generate DSA keys
def generate_dsa_keys(bits):
    q = generate_large_prime(160)  # 160-bit prime for q
    p = 2
    while not is_prime(p):
        p = q * random.randint(2**159, 2**160) + 1  # 1024 to 2048-bit prime for p
    g = pow(random.randint(2, p - 2), (p - 1) // q, p)  # g is a generator of the subgroup

    # Private key (x) is a random number from [1, q-1]
    x = random.randint(1, q - 1)
    # Public key (y) calculation
    y = pow(g, x, p)

    return p, q, g, y, x

# Function to sign a message using DSA
def sign_message(message, p, q, g, x):
    hash_value = int(hashlib.sha1(message.encode()).hexdigest(), 16)
    while True:
        k = random.randint(1, q - 1)
        r = pow(g, k, p) % q
        if r != 0:
            break
    s = (pow(k, -1, q) * (hash_value + x * r)) % q
    return r, s

# Function to verify a signature
def verify_signature(message, r, s, p, q, g, y):
    if not (0 < r < q) or not (0 < s < q):
        return False
    w = pow(s, -1, q)
    hash_value = int(hashlib.sha1(message.encode()).hexdigest(), 16)
    u1 = (hash_value * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    return v == r

# Example usage
p, q, g, y, x = generate_dsa_keys(160)
message = "Hello, DSA!"
r, s = sign_message(message, p, q, g, x)
print("Message:", message)
print("Signature (r, s):", r, s)
print("Signature verified:", verify_signature(message, r, s, p, q, g, y))
