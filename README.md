# Firma

1. mix deps.get
This will load all the dependecies

2. mix test test/firma_test.exs
Run firma test sign a payload,  generates files jws_header.txt and buk.json, load the contents of files and validate the signature

3. testcripto.py sign a payload generates files jws_header.txt and buk.json

4. validate.py load files jws_header.txt and buk.json and validate the signature

validate.py raises and exception jwcrypto.jws.InvalidJWSSignature: Verification failed for all signatures["Failed: [InvalidJWSSignature('Verification failed')]"], when validates the elixir generated files. If you try validate.py with the files generated by testcripto.py, the signature is validated and no exception is raised

openssl req -x509 -newkey rsa:2048 -nodes -keyout testkey.pem -out testcert.pem -sha256 -days 365 -pubkey 

python testcripto.py genera test_compact.txt test_header.txt y  test.json
mix test test/firma_test.exs python testcripto.py genera test_compact.txt test_header.txt y  test.json
python validate.py valida
mix test test/validate_test.exs valida



