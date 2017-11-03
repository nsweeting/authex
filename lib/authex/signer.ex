defmodule Authex.Signer do
  alias Authex.Config
  alias Authex.Signer

  defstruct [
    :jwk,
    :jws,
  ]

  @secret Config.secret()
  @default_alg Config.get(:default_alg, :hs256)

  def new(options \\ []) do
    secret = Keyword.get(options, :secret, @secret)
    alg    = Keyword.get(options, :alg, @default_alg)
  
    %Signer{}
    |> put_jwk(secret)
    |> put_jws(alg)
  end

  def compact(%Signer{jwk: jwk, jws: jws}, claims) do
    {_, compact_token} = jwk
    |> JOSE.JWT.sign(jws, claims)
    |> JOSE.JWS.compact()

    compact_token
  end

  def put_jwk(signer, secret) do
    jwk = %{"kty" => "oct", "k" => secret}
    %{signer | jwk: jwk}
  end

  def put_jws(signer, :hs256) do
    %{signer | jws: %{"alg" => "HS256"}}
  end
  def put_jws(signer, :hs384) do
    %{signer | jws: %{"alg" => "HS384"}}
  end
  def put_jws(signer, :hs512) do
    %{signer | jws: %{"alg" => "HS512"}}
  end
  def put_jws(_, _) do
    raise ArgumentError, "alg not implemented"
  end
end
