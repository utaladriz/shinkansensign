import sys
from jwcrypto import jwk, jws
from jwcrypto.common import json_encode, base64url_encode
import json
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import base64



with open("bukpubkey.pem", "rb") as pemfile:
      bukpubkey = jwk.JWK.from_pem(pemfile.read())
with open("shinkansenpubkey.pem", "rb") as pemfile:
    shinkansenpubkey = jwk.JWK.from_pem(pemfile.read())
with open("bukkey.pem", "rb") as pemfile:
    bukkey = jwk.JWK.from_pem(pemfile.read(),"1234567890".encode())
with open("shinkansenkey.pem", "rb") as pemfile:
    shinkansenkey = jwk.JWK.from_pem(pemfile.read(),"1234567890".encode())
with open("bukcert.pem", "rb") as pemfile:
    bukcert = pemfile.read()
with open("shinkansencert.pem", "rb") as pemfile:
    shinkansencert = pemfile.read()
shinkansencert = x509.load_pem_x509_certificate(shinkansencert)
bukcert = x509.load_pem_x509_certificate(bukcert)

jwstoken = jws.JWS()
with open("jws_header.txt", "r") as header_file:
    header_str = header_file.read()
with open("buk.json", "r") as json_file:
    json_str = json_file.read()
jwstoken = jws.JWS()
jwstoken.deserialize(header_str)
jwstoken.verify(bukpubkey, alg="PS256", detached_payload=json_str.encode('utf-8'))





