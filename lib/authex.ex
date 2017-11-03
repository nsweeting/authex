defmodule Authex do
  alias Authex.{
    Blacklist,
    Serializer,
    Signer,
    Token,
    Verifier,
  }

  @doc """
  Creates a new Authex.Token struct from the given claims and options

  ## Parameters

    - claims: A keyword list of JWT claims.
    - options: A keyword list of options.

  ## Options
    * `:time` - the base time (timestamp format) in which to use.
    * `:ttl` - the TTL for the token.

  ## Examples

      iex> Authex.token([sub: 1, jti: "test"], [time: 1500000000, ttl: 10])
      %Authex.Token{
        aud: nil, exp: 1500000010, iat: 1500000000, iss: nil,
        jti: "test", nbf: 1499999999,
        scopes: [], sub: 1}
  """
  def token(claims \\ [], options \\ []) do
    Token.new(claims, options)
  end

  @doc """
  Signs an Authex.Token struct, creating a compact token.

  ## Parameters

    - token: An Authex.Token struct.
    - options: A keyword list of options.

  ## Options
    * `:secret` - the secret key to sign the token with.
    * `:alg` - the algorithm to sign the token with.

  """
  def sign(%Token{} = token, options \\ []) do
    signer = Signer.new(options)
    claims = Token.get_claims(token)
    Signer.compact(signer, claims)
  end

  @doc """
  Verifies a compact token.

  ## Parameters

    - compact_token: A compact token binary.
    - options: A keyword list of options.

  ## Options
    * `:secret` - the secret key to verify the token with.
    * `:alg` - the algorithm to verify the token with.

  """
  def verify(compact_token, options \\ []) do
    compact_token
    |> Verifier.new(options)
    |> Verifier.run()
  end

  @doc """
  Turns a token into a usable resource using a serializer module.

  ## Parameters

    - token: An Authex.Token struct.

  """
  def from_token(%Token{} = token) do
    Serializer.from_token(token)
  end
  def from_token(compact_token) when is_binary(compact_token) do
    case verify(compact_token) do
      {:ok, token} -> from_token(token)
      error -> error
    end
  end

  @doc """
  Turns a resource into a compact token using a serializer module.

  ## Parameters

    - resource: Any usable resource.

  """
  def for_token(resource) do
    Serializer.for_compact_token(resource)
  end

  def blacklisted?(token_or_jti) do
    Blacklist.get(token_or_jti)
  end

  def blacklist(token_or_jti) do
    Blacklist.set(token_or_jti)
  end

  def unblacklist(token_or_jti) do
    Blacklist.del(token_or_jti)
  end

  def current_user(%{private: private}) do
    Map.fetch(private, :authex_current_user)
  end
  def current_user(_) do
    :error
  end
end
