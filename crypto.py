from Crypto.Util.number import getPrime
import secrets
import hashlib


class ElGamal():

    def __init__(self, bits=2048):
        self.p = getPrime(bits)
        self.g = 2

        pedersen_secret = secrets.randbelow(self.p - 2) + 1
        self.h_commit = pow(self.g, pedersen_secret, self.p)

        self.private_key = None
        self.public_key = None


    def key_gen(self):

        if self.private_key is not None or self.public_key is not None:
            return

        self.private_key = secrets.randbelow(self.p - 2) + 1
        public_key_component = pow(self.g, self.private_key, self.p)
        self.public_key = {
            "p": self.p,
            "g": self.g,
            "h": public_key_component
        }
        return self.public_key, self.private_key
    
    def encrypt(self, plain):
        if self.public_key is None:
            raise Exception("Public Key is empty, use .key_gen to initialize")

        p = self.public_key["p"]
        g = self.public_key["g"]
        h = self.public_key["h"]

        ephemeral_key = secrets.randbelow(p - 2) + 1
        
        c1 = pow(g, ephemeral_key, p)

        shared_secret = pow(h, ephemeral_key, p)

        c2 = (plain * shared_secret) % p

        return (c1, c2)

    def decrypt(self, ciphertext):
        if self.private_key is None or self.public_key is None:
            raise Exception("Key pair is empty, use .key_gen to initialize")

        p = self.public_key["p"]

        c1, c2 = ciphertext

        shared_secret = pow(c1, self.private_key, p)

        inverse_secret = pow(shared_secret, -1, p)

        plain = (c2 * inverse_secret) % p

        return plain

    def encrypt_exponential(self, x: int):
        if self.public_key is None:
            raise Exception("Public Key is empty, use .key_gen to initialize")

        p = self.public_key["p"]
        g = self.public_key["g"]
        h = self.public_key["h"]

        r = secrets.randbelow(self.p - 2) + 1
        c1 = pow(g, r, p)
        c2 = pow(g, x, p) * pow(h, r, p) % p  # g^x * h^r

        return {"c1": c1, "c2": c2, "r": r}



def commit(value, elgamal: ElGamal):
    
    p = elgamal.p
    g = elgamal.g
    h_commit = elgamal.h_commit
    
    r = secrets.randbelow(p - 2) + 1
    gx = pow(g, value, p)
    hr = pow(h_commit, r, p)

    commitment = (gx * hr) % p

    return {
        "commitment": commitment,
        "r": r
    }


def fiat_shamir(*values):

    data = ""
    for value in values:
        data += str(value)

    digest = hashlib.sha256(data.encode()).hexdigest()

    return int(digest, 16)


def generate_proof(
        commitment,
        value,
        randomness,
        elgamal: ElGamal
):

    p = elgamal.p
    g = elgamal.g
    h_commit = elgamal.h_commit
    # Random temp values
    u1 = secrets.randbelow(p - 2) + 1
    u2 = secrets.randbelow(p - 2) + 1

    # Temp commitment
    T = pow(g, u1, p) * pow(h_commit, u2, p) % p
    
    # Challenge
    c = fiat_shamir(commitment, T)

    # Responses

    s1 = u1 + c*value
    s2 = u2 + c*randomness

    return {
        "T": T,
        "s1": s1,
        "s2": s2
    }


def verify_proof(
        commitment,
        proof,
        elgamal: ElGamal
):
    p = elgamal.p
    g = elgamal.g
    h_commit = elgamal.h_commit

    T = proof["T"]
    s1 = proof["s1"]
    s2 = proof["s2"]

    # Rebuild challenge
    c = fiat_shamir(commitment, T)

    left = pow(g, s1, p) * pow(h_commit, s2, p) % p

    right = T * pow(commitment, c, p) % p

    return left == right


# Descompose x, 7 bits fit in range [0, 127]
def bit_decompose(x: int, n_bits: int = 7):
    assert 0 <= x <= 120, f"x={x} outside range [0, 120]"
    bits = [(x >> i) & 1 for i in range(n_bits)]
    assert sum(b * (2**i) for i, b in enumerate(bits)) == x  # sanity check
    return bits

# commitment for each bit
def commit_bits(bits: list, elgamal: ElGamal):
    commitments = []
    for b in bits:
        data = commit(b, elgamal)
        commitments.append(data)
    return commitments


