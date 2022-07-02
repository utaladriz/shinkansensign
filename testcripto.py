import sys
from jwcrypto import jwk, jws
from jwcrypto.common import json_encode, base64url_encode
import json
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import base64


payload = '''{"data":"test"}'''

with open("testkey.pem", "rb") as pemfile:
    testkey = jwk.JWK.from_pem(pemfile.read())
with open("testcert.pem", "rb") as pemfile:
    testcert = x509.load_pem_x509_certificate(pemfile.read())

testder = testcert.public_bytes(serialization.Encoding.DER)
jwstoken = jws.JWS(payload.encode('utf-8'))
x5c = base64.b64encode(testder).decode('ascii')
jwstoken.add_signature(testkey, alg=None, protected={"alg": "PS256", "b64":True, "x5c": [x5c], "crit": ["b64"]})
signature = base64url_encode(jwstoken.objects["signature"])
protected = base64url_encode(jwstoken.objects["protected"])
sig = f"{protected}..{signature}"
with open("test_header.txt", "w") as header_file:
    header_file.write(f"{protected}..{signature}")
with open("test.json", "w") as json_file:
    json_file.write(payload)
with open("test_compact.txt", "w") as compact_file:
    compact_file.write(jwstoken.serialize(True))    





