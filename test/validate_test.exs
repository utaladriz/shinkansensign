defmodule ValidateTest do
  use ExUnit.Case
  alias X509.Certificate
  alias X509.PublicKey
  alias JOSE.JWS
  alias JOSE.JWK
  require OK

  test "firma y validación" do

    {:ok, {valid_dettached, valid_compact}} =  OK.for do
      payload <- File.read("test.json")
      header <- File.read("test_header.txt")
      compact <- File.read("test_compact.txt")
      pem <- File.read("testcert.pem")
      x509 <- Certificate.from_pem(pem)
      public_key = JWK.from_pem(PublicKey.to_pem(Certificate.public_key(x509)))
    after
      [protected | [signature]] = String.split(header,"..")
      valid_compact = IO.inspect(JWS.verify(public_key, compact)) |> elem(0)
      valid_dettached = IO.inspect(JWS.verify(public_key, { %{alg: :jose_jws_alg_rsa_pss}, %{"payload" => Base.encode64(payload), "protected" => protected, "signature" => signature}})) |> elem(0)
      {valid_dettached, valid_compact}
    end
    assert valid_compact
    assert valid_dettached
  end
end
