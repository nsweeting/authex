defmodule Authex do
  @moduledoc """
  To come...
  """

  alias Authex.{
    Blacklist,
    Serializer,
    Signer,
    Token,
    Verifier,
  }

  @doc """
  Creates a new Authex.Token struct from the given claims and options.

  Returns an `Authex.Token` struct.

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
  @spec token(list, list) :: Authex.Token.t
  def token(claims \\ [], options \\ []) do
    Token.new(claims, options)
  end

  @doc """
  Signs an Authex.Token struct, creating a compact token.

  Returns a binary compact token.

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
  @spec sign(Authex.Token.t, list) :: binary
  def sign(%Token{} = token, options \\ []) do
    signer = Signer.new(options)
    claims = Token.get_claims(token)
    Signer.compact(signer, claims)
  end

  @doc """
  Verifies a compact token.

  Returns `{:ok, %Authex.Token{}}` if the token is valid.

  Otherwise, returns `{:error, :reason}`

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
  @spec verify(binary, list) :: {:ok, Authex.Token.t} | {:error, atom}
  def verify(compact_token, options \\ []) do  
    compact_token
    |> Verifier.new(options)
    |> Verifier.run()
  end

  @doc """
  Turns a token into a usable data structure using a serializer module.

  Returns any term defined by the serializer.

  Otherwise, returns `:error`. 

  ## Parameters

    - token: An Authex.Token struct or compact token binary.

  ## Examples

      iex> [sub: 1] |> Authex.token() |> Authex.sign() |> Authex.from_token()
      %{id: 1, scopes: []}
  """
  @spec from_token(Authex.Token.t) :: term | {:error, atom}
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

  Returns a binary compact token.

  ## Parameters

    - resource: Any usable data structure.

  ## Examples

      iex> %{id: 1} |> Authex.for_token() |> is_binary()
      true
  """
  @spec for_token(term) :: Authex.Token.t | :error
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
  Gets the current user from a Plug.Conn.

  Returns a term defined by a serializer.

  ## Parameters

    - conn: A Plug.Conn struct.
  """
  @spec current_user(Plug.Conn.t) :: {:ok, term} | :error
  def current_user(%{private: private} = _conn) do
    Map.fetch(private, :authex_current_user)
  end
  def current_user(_) do
    :error
  end

  @doc """
  Gets the current scopes from a Plug.Conn.

  Returns a list of scopes.

  ## Parameters

    - conn: A Plug.Conn struct.
  """
  @spec current_scopes(Plug.Conn.t) :: {:ok, list} | :error
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
