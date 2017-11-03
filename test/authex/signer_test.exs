defmodule Authex.SignerTest do
  use ExUnit.Case

  alias Authex.Signer

  test "new/1 uses the config secret by default" do
    signer = Signer.new()
    refute signer.jwk == %{"kty" => "oct", "k" => "secret"} 
    signer = Signer.new([secret: "secret"])
    assert signer.jwk == %{"kty" => "oct", "k" => "secret"}
  end

  test "new/1 allows the secret to be set for signing" do
    signer = Signer.new(secret: "secret")
    assert signer.jwk == %{"kty" => "oct", "k" => "secret"}
  end

  test "new/1 defaults to HS256 alg for signing" do
    signer = Signer.new()
    assert signer.jws == %{"alg" => "HS256"}
  end

  test "new/1 allows HS256 alg to be used for signing" do
    signer = Signer.new(alg: :hs256)
    assert signer.jws == %{"alg" => "HS256"}
  end

  test "new/1 allows HS384 alg to be used for signing" do
    signer = Signer.new(alg: :hs384)
    assert signer.jws == %{"alg" => "HS384"}
  end

  test "new/1 allows HS512 alg to be used for signing" do
    signer = Signer.new(alg: :hs512)
    assert signer.jws == %{"alg" => "HS512"}
  end
end
