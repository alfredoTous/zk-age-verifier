from Crypto.Util.number import getPrime
import secrets


class ElGamal():

    def __init__(self, bits=2048):
        self.p = getPrime(bits)
        self.g = 2

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


def main():
    elgamal = ElGamal()
    elgamal.key_gen()
    print("Ya")
    plain = 25
    ct = elgamal.encrypt(plain)
#    d = elgamal.decrypt(ct)
#
#    print("ORIGINAL:", plain)
#
#    print("\nCIPHERTEXT:", ct)
#
#    print("\nDECRYPTED:", d)
#    
#    print(f"\n\npublic_key: {elgamal.public_key}\n\n\nprivate_key: {elgamal.private_key}")
#
if __name__ == "__main__":
    main()
        

