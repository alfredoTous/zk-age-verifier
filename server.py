from fastapi import FastAPI
from pydantic import BaseModel

from crypto import ElGamal


app = FastAPI()

AGE_LIMIT = 18

elgamal = ElGamal()
elgamal.key_gen()


class VerifyRequest(BaseModel):
    ciphertext: dict
    proof: dict


@app.get("/policy")
def policy():
    if elgamal.public_key is None:
        raise ValueError("Public key not generated")
    response = elgamal.public_key.copy()
    response.update({"L": 18})
    return response


@app.post("/verify")
def verify(data: VerifyRequest):
    output = "DENY"
    proof = data.proof

    # FAKE VERIFY TEMPORAL
    valid = proof.get("valid", False)

    if valid:
        output = "ALLOW"

    return {
        "result": output
    }
        
