defmodule Authex.Signer do
  alias Authex.Config
  alias Authex.Signer

  @type t :: %__MODULE__{
    jwk:         integer,
    jws:         integer
  }

  defstruct [
    :jwk,
    :jws,
  ]

  @default_opts [
    secret: Config.secret(),
    alg:    Config.default_alg()
  ]


  @doc """
  Creates a new Authex.Signer struct from the options.

  ## Parameters

    - options: A keyword list of options.

  ## Options
    * `:secret` - the secret to sign the token with.
    * `:alg` - the algorithm to sign the token with.
  """
  def new(options \\ []) do
    options = Keyword.merge(@default_opts, options)
    secret  = Keyword.get(options, :secret)
    alg     = Keyword.get(options, :alg)
  
    %Signer{}
    |> put_jwk(secret)
    |> put_jws(alg)
  end

  @doc """
  Creates a new binary compact token from the Authex.Signer struct and
  binary claims map.

  ## Parameters

    - signer - An Authex.Signer struct.
    - cliams: A binary claims map.

  ## Examples

      iex> token = Authex.Token.new()
      iex> claims = Authex.Token.get_claims(token)
      iex> signer = Authex.Signer.new()
      iex> signer |> Authex.Signer.compact(claims) |> is_binary() 
      true
  """
  def compact(%Signer{jwk: jwk, jws: jws}, claims) do
    {_, compact_token} = jwk
    |> JOSE.JWT.sign(jws, claims)
    |> JOSE.JWS.compact()

    compact_token
  end

  @doc false
  def put_jwk(signer, secret) do
    jwk = %{"kty" => "oct", "k" => secret}
    %{signer | jwk: jwk}
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
    raise ArgumentError, "alg not implemented"
  end
end
