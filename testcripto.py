import sys
from jwcrypto import jwk, jws
from jwcrypto.common import json_encode, base64url_encode
import json
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import base64


payload_buk = '''{"document": {
        "header": {
            "message_id": "c7bdf779-144b-4e5f-b6f0-9b361ddaf6c9",
            "creation_date": "2022-04-08T18:25:43-04:00",
            "sender": {
                "fin_id_schema": "SHINKANSEN",
                "fin_id": "BUK"
            },
            "receiver": {
                "fin_id_schema": "SHINKANSEN",
                "fin_id": "SHINKANSEN"
            }
        },
        "transactions": [
            {
                "transaction_type": "payout",
                "transaction_id": "ee19538c-3a23-47c9-ba8e-472a7500de7c",
                "currency": "CLP",
                "amount": "30000",
                "execution_date": "2022-04-11T10:30:00-03:00",
                "description": "Salary payment",
                "debtor": {
                    "name": "Buk SpA",
                    "email": "romulo.gallegos@shinkasen.finance",
                    "identification": {
                        "id_schema": "CLID",
                        "id": "12383287-6"
                    },
                    "financial_institution": {
                        "fin_id_schema": "SHINKANSEN",
                        "fin_id": "BICE"
                    },
                    "account_type" : "debit",
                    "account": "12335455"
                },
                "creditor": {
                    "name": "Romulo Gallegos",
                    "email": "romulo.gallegos@shinkasen.finance",
                    "identification": {
                        "id_schema": "CLID",
                        "id": "12383287-6"
                    },
                    "financial_institution": {
                        "fin_id_schema": "SHINKANSEN",
                        "fin_id": "SCOTIABANKCL"
                    },
                    "account_type" : "debit",
                    "account": "12335455"
                }
            }
        ]
    }}'''

with open("bukpubkey.pem", "rb") as pemfile:
    bukpubkey = jwk.JWK.from_pem(pemfile.read())
with open("bukkey.pem", "rb") as pemfile:
    bukkey = jwk.JWK.from_pem(pemfile.read(),"1234567890".encode())
with open("bukcert.pem", "rb") as pemfile:
    bukcert = pemfile.read()

bukcert = x509.load_pem_x509_certificate(bukcert)
bukder = bukcert.public_bytes(serialization.Encoding.DER)
jwstoken = jws.JWS(payload_buk.encode('utf-8'))
x5c = base64.b64encode(bukder).decode('ascii')
jwstoken.add_signature(bukkey, None, {"alg": "PS256", "b64": False, "x5c": [x5c], "crit": ["b64"]})
signature = base64url_encode(jwstoken.objects["signature"])
protected = base64url_encode(jwstoken.objects["protected"])
sig = f"{protected}..{signature}"
with open("jws_header.txt", "w") as header_file:
    header_file.write(f"{protected}..{signature}")
with open("buk.json", "w") as json_file:
    json_file.write(payload_buk)





