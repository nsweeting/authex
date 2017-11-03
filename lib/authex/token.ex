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

  @default_ttl Config.get(:default_ttl, 3600)
  @default_iss Config.get(:default_iss)
  @default_aud Config.get(:default_aud)
  @jti_mfa Config.get(:jti_mfa, {UUID, :uuid4, [:hex]})

  @spec new(list, list) :: t
  def new(claims \\ [], options \\ []) do
    time    = Keyword.get(options, :time, :os.system_time(:seconds))
    ttl     = Keyword.get(options, :ttl, @default_ttl)

    sub     = Keyword.get(claims, :sub)
    aud     = Keyword.get(claims, :aud, @default_aud)
    iss     = Keyword.get(claims, :iss, @default_iss)
    jti     = Keyword.get(claims, :jti, @jti_mfa)
    scopes  = Keyword.get(claims, :scopes, [])

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

  @spec from_map(map) :: t
  def from_map(claims) when is_map(claims) do
    claims = Enum.reduce(claims, %{}, fn({key, val}, acc) -> 
      Map.put(acc, String.to_atom(key), val)
    end)
    struct(__MODULE__, claims)
  end

  @spec get_claims(t) :: map
  def get_claims(token) do
    token
    |> Map.from_struct()
    |> Map.to_list()
    |> Enum.map(fn({key, val}) -> {Atom.to_string(key), val} end)
    |> Map.new()
  end

  @spec put_nbf(t, integer) :: t
  def put_nbf(token, time) do
    %{token | nbf: time - 1}
  end
  
  @spec put_iat(t, integer) :: t
  def put_iat(token, time) do
    %{token | iat: time}
  end

  @spec put_exp(t, integer, integer) :: t
  def put_exp(token, time, ttl) when is_integer(ttl) do
    %{token | exp: time + ttl}
  end
  def put_exp(token, time, _) do
    %{token | exp: time + @default_ttl}
  end

  @spec put_jti(t, binary | tuple) :: t
  def put_jti(token, {mod, fun, args}) do
    %{token | jti: apply(mod, fun, args)}
  end
  def put_jti(token, jti)when is_binary(jti) do
    %{token | jti: jti}
  end

  @spec put_sub(t, binary) :: t
  def put_sub(token, sub) do
    %{token | sub: sub}
  end

  @spec put_iss(t, binary) :: t
  def put_iss(token, iss) do
    %{token | iss: iss}
  end

  @spec put_aud(t, binary) :: t
  def put_aud(token, aud) do
    %{token | aud: aud}
  end

  @spec put_scopes(t, list) :: t
  def put_scopes(token, scopes) do
    %{token | scopes: scopes}
  end

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
