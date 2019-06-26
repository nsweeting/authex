defmodule Authex.Signer do
  @moduledoc false

  alias Authex.{Signer, Token}

  defstruct [
    :jwk,
    :jws
  ]

  @doc false
  def new(module, opts \\ []) do
    opts = build_options(module, opts)

    %Signer{}
    |> put_jwk(opts.secret)
    |> put_jws(opts.alg)
  end

  @doc false
  def compact(signer, token) do
    claims = Token.get_claims(token)

    {_, compact_token} =
      signer.jwk
      |> JOSE.JWT.sign(signer.jws, claims)
      |> JOSE.JWS.compact()

    compact_token
  end

  @doc false
  def put_jwk(signer, secret) when is_binary(secret) do
    jwk = %{"kty" => "oct", "k" => secret}
    %{signer | jwk: jwk}
  end

  @doc false
  def put_jwk(_, _) do
    raise Authex.Error, "secret cannot be nil"
  end

  @doc false
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
    raise Authex.Error, "alg not implemented"
  end

  defp build_options(module, opts) do
    Enum.into(opts, %{
      alg: Authex.config(module, :default_alg, :hs256),
      secret: Authex.config(module, :secret)
    })
  end
end
