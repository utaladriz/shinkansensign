defmodule FirmaTest do
  use ExUnit.Case
  alias X509.Certificate
  alias JOSE.JWS
  alias JOSE.JWK
  require OK

  test "firma y validación" do
    payload = ~s'{"data":"test"}'

    :ets.insert(:jose_jwa, {{:rsa_sign, :rsa_pkcs1_pss_padding}, {:public_key, [rsa_padding: :rsa_pkcs1_pss_padding, rsa_pss_saltlen: -1]}})
    {:ok, compact} = OK.for do
      private <- File.read("testkey.pem")
      private_jwk = JWK.from_pem(private)
      certificate <- File.read("testcert.pem")
      x509 <- Certificate.from_pem(certificate)
      signed_ps256 = JWS.sign(private_jwk, payload, %{ "alg" => "PS256", "b64"=> true, "x5c" => [Base.encode64(Certificate.to_der(x509))], "crit"=>["b64"] })
      %{"payload"=> _, "protected" => protected, "signature" => signature} = signed_ps256 |> elem(1)
      compact = JWS.compact(signed_ps256) |> elem(1)
    after
      File.write("test.json", payload)
      File.write("test_header.txt", "#{protected}..#{signature}")
      File.write("test_compact.txt", compact)
      compact
    end

    assert true
  end
end
