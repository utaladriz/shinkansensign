defmodule FirmaTest do
  use ExUnit.Case
  alias X509.Certificate
  alias JOSE.JWS
  alias JOSE.JWK
  require OK

  test "firma y validación" do
    payload = ~s'{"document": {
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
    }}'


    {:ok, public_jwk} = OK.for do
      private <- File.read("bukkey.pem")
      private_jwk = JWK.from_pem("1234567890", private)
      public <- File.read("bukpubkey.pem")
      public_jwk = JWK.from_pem(public)
      certificate <- File.read("bukcert.pem")
      x509 <- Certificate.from_pem(certificate)
      signed_ps256 = JWS.sign(private_jwk, payload, %{ "alg" => "PS256", "b64" => false, "x5c" => [Base.encode64(Certificate.to_der(x509))], "crit" => ["b64"] })
      %{"payload"=> _, "protected" => protected, "signature" => signature} = signed_ps256 |> elem(1)
    after
      File.write("buk.json", payload)
      File.write("jws_header.txt", "#{protected}..#{signature}")
      public_jwk
    end

    {:ok, valid} =  OK.for do
      payload <- File.read("buk.json")
      header <- File.read("jws_header.txt")
    after
      [protected | [signature]] = String.split(header,"..")
      IO.inspect(JWS.verify(public_jwk, { %{alg: :jose_jws_alg_rsa_pss}, %{"payload" => Base.encode64(payload), "protected" => protected, "signature" => signature}})) |> elem(0)
    end
    assert valid
  end
end
