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

      iex> token = Authex.token([sub: 1], [ttl: 60])
      iex> with %Authex.Token{sub: sub} <- token, do: sub
      1
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

  ## Examples

      iex> Authex.token() |> Authex.sign() |> is_binary()
      true
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

  ## Examples

      iex> {:ok, token} = [sub: 1] |> Authex.token() |> Authex.sign() |> Authex.verify()
      iex> with %Authex.Token{sub: sub} <- token, do: sub
      1
  """
  def verify(compact_token, options \\ []) do
    compact_token
    |> Verifier.new(options)
    |> Verifier.run()
  end

  @doc """
  Turns a token into a usable data structure using a serializer module.

  ## Parameters

    - token: An Authex.Token struct or compact token binary.

  ## Examples

      iex> [sub: 1] |> Authex.token() |> Authex.sign() |> Authex.from_token()
      %{id: 1, scopes: []}
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
  Turns a usable data structure into a compact token using a serializer module.

  ## Parameters

    - resource: Any usable data structure.

  ## Examples

      iex> %{id: 1} |> Authex.for_token() |> is_binary()
      true
  """
  def for_token(resource) do
    Serializer.for_compact_token(resource)
  end

  @doc false
  def blacklisted?(token_or_jti) do
    Blacklist.get(token_or_jti)
  end

  @doc false
  def blacklist(token_or_jti) do
    Blacklist.set(token_or_jti)
  end

  @doc false
  def unblacklist(token_or_jti) do
    Blacklist.del(token_or_jti)
  end

  @doc """
  Returns the current user from a Plug.Conn.

  ## Parameters

    - conn: A Plug.Conn struct.
  """
  def current_user(%{private: private} = _conn) do
    Map.fetch(private, :authex_current_user)
  end
  def current_user(_) do
    :error
  end

  @doc """
  Returns the current scopes from a Plug.Conn.

  ## Parameters

    - conn: A Plug.Conn struct.
  """
  def current_scopes(%{private: private} = _conn) do
    case Map.fetch(private, :authex_token) do
      {:ok, token} -> Map.fetch(token, :scopes)
      :error -> :error
    end
  end
  def current_scopes(_) do
    :error
  end
end
