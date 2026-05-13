import requests
from crypto import ElGamal

SERVER = "http://127.0.0.1:8000"

policy = requests.get(f"{SERVER}/policy").json()

print("\nPOLICY:", policy)

public_key = policy.copy()
public_key.pop("L")
print("SEXO\n\n", public_key)
elgamal = ElGamal()
elgamal.public_key = public_key
age = 25
ciphertext = elgamal.encrypt(age)

# FAKE PROOF
# =========================

proof = {
    "valid": age >= policy["L"]
}

payload = {
    "ciphertext": ciphertext,
    "proof": proof
}


# =========================
# SEND VERIFY
# =========================

response = requests.post(f"{SERVER}/verify", json=payload)

print("\nSERVER RESPONSE:")
print(response.json())
