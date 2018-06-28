defmodule Authex.Signer do
  alias Authex.Signer
  alias Authex.Token

  defstruct [
    :jwk,
    :jws
  ]

  @type option ::
          {:secret, binary}
          | {:alg, atom}

  @type options :: [option]

  @type t :: %__MODULE__{
          jwk: integer | nil,
          jws: integer | nil
        }

  @doc """
  Creates a new Authex.Signer struct from the options.

  ## Parameters

    - auth: An `Authex` module.
    - options: A keyword list of options.

  ## Options
    * `:secret` - the secret to sign the token with.
    * `:alg` - the algorithm to sign the token with.
  """
  def new(auth, opts \\ []) do
    opts = build_options(auth, opts)

    %Signer{}
    |> put_jwk(opts.secret)
    |> put_jws(opts.alg)
  end

  @doc """
  Creates a new binary compact token from the `Authex.Signer` and `Authex.Token`
  structs.

  ## Parameters

    - signer - An `Authex.Signer` struct.
    - token: An `Authex.Token` struct.
  """
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

  defp build_options(auth, opts) do
    Enum.into(opts, %{
      alg: auth.config(:default_alg, :hs256),
      secret: auth.config(:secret)
    })
  end
end
