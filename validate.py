import sys
from jwcrypto import jwk, jws
from jwcrypto.common import json_encode, base64url_encode
import json
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import base64



with open("testcert.pem", "rb") as pemfile:
    testcert = x509.load_pem_x509_certificate(pemfile.read())


jwstoken = jws.JWS()
with open("test_header.txt", "r") as header_file:
    header_str = header_file.read()
with open("test.json", "r") as json_file:
    json_str = json_file.read()
jwstoken = jws.JWS()
jwstoken.deserialize(header_str)
public_key = jwk.JWK.from_pem(testcert.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
jwstoken.verify(public_key, alg="PS256", detached_payload=json_str)





