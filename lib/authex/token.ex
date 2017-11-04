defmodule Authex.Token do
  alias Authex.Config
  alias Authex.Token

  @type t :: %__MODULE__{
    nbf:    integer,
    exp:    integer,
    iat:    integer,
    jti:    binary,
    sub:    binary | integer,
    iss:    binary,
    aud:    binary,
    scopes: list
  }

  defstruct [
    nbf:     nil,
    exp:     nil,
    iat:     nil,
    jti:     nil,
    sub:     nil,
    iss:     nil,
    aud:     nil,
    scopes:  [],
  ]

  @doc """
  Creates a new Authex.Token struct from the given claims and options

  ## Parameters

    - claims: A keyword list of JWT claims.
    - options: A keyword list of options.

  ## Options
    * `:time` - the base time (timestamp format) in which to use.
    * `:ttl` - the TTL for the token.

  ## Examples

      iex> token = Authex.Token.new([sub: 1], [ttl: 60])
      iex> with %Authex.Token{sub: sub} <- token, do: sub
      1
  """
  @spec new(list, list) :: t
  def new(claims \\ [], options \\ []) do
    claims  = Config.options(:claims, claims)
    options = Config.options(:token, options)

    time    = Keyword.get(options, :time, :os.system_time(:seconds))
    ttl     = Keyword.get(options, :ttl)
    sub     = Keyword.get(claims, :sub)
    aud     = Keyword.get(claims, :aud)
    iss     = Keyword.get(claims, :iss)
    jti     = Keyword.get(claims, :jti)
    scopes  = Keyword.get(claims, :scopes)

    %Token{}
    |> put_iat(time)
    |> put_nbf(time)
    |> put_exp(time, ttl)
    |> put_jti(jti)
    |> put_sub(sub)
    |> put_aud(aud)
    |> put_iss(iss)
    |> put_scopes(scopes)
  end

  @doc false
  @spec from_map(map) :: t
  def from_map(claims) when is_map(claims) do
    claims = Enum.reduce(claims, %{}, fn({key, val}, acc) -> 
      Map.put(acc, String.to_atom(key), val)
    end)
    struct(__MODULE__, claims)
  end

  @doc false
  @spec get_claims(t) :: map
  def get_claims(token) do
    token
    |> Map.from_struct()
    |> Map.to_list()
    |> Enum.map(fn({key, val}) -> {Atom.to_string(key), val} end)
    |> Enum.reject(fn({_, val}) -> val == nil end)
    |> Map.new()
  end

  @doc false
  @spec put_nbf(t, integer) :: t
  def put_nbf(token, time) do
    %{token | nbf: time - 1}
  end
  
  @doc false
  @spec put_iat(t, integer) :: t
  def put_iat(token, time) do
    %{token | iat: time}
  end

  @doc false
  @spec put_exp(t, integer, integer) :: t
  def put_exp(token, time, ttl) do
    %{token | exp: time + ttl}
  end

  @doc false
  @spec put_jti(t, binary | tuple) :: t
  def put_jti(token, false) do
    %{token | jti: nil}
  end
  def put_jti(token, {mod, fun, args}) do
    %{token | jti: apply(mod, fun, args)}
  end
  def put_jti(token, jti) when is_binary(jti) do
    %{token | jti: jti}
  end

  @doc false
  @spec put_sub(t, binary) :: t
  def put_sub(token, sub) do
    %{token | sub: sub}
  end

  @doc false
  @spec put_iss(t, binary) :: t
  def put_iss(token, iss) do
    %{token | iss: iss}
  end

  @doc false
  @spec put_aud(t, binary) :: t
  def put_aud(token, aud) do
    %{token | aud: aud}
  end

  @doc false
  @spec put_scopes(t, list) :: t
  def put_scopes(token, scopes) do
    %{token | scopes: scopes}
  end

  @doc false
  def has_scope?(%Token{scopes: current_scopes}, scopes) do
    has_scope?(current_scopes, scopes)
  end
  def has_scope?(current_scopes, scopes)
  when is_list(current_scopes) and is_list(scopes) do
    Enum.find(scopes, false, fn scope ->
      Enum.member?(current_scopes, scope)
    end)
  end
  def has_scope?(_, _) do
    false
  end
end
