defmodule Authex.Token do
  @moduledoc """
  A struct wrapper for token claims.

  Typically, we shouldnt need to directly interact with this module. Rather, we
  should use the `c:Authex.token/2` callback defined in our auth module.
  """

  alias Authex.Token

  defstruct nbf: nil,
            exp: nil,
            iat: nil,
            jti: nil,
            sub: nil,
            iss: nil,
            aud: nil,
            scopes: [],
            meta: %{}

  @type t :: %__MODULE__{
          nbf: integer | nil,
          exp: integer | nil,
          iat: integer | nil,
          jti: binary | nil,
          sub: binary | integer | nil,
          iss: binary | nil,
          aud: binary | nil,
          scopes: list,
          meta: map
        }

  @type claim ::
          {:sub, binary | integer}
          | {:aud, binary}
          | {:iss, binary}
          | {:jti, binary}
          | {:scopes, list}
          | {:meta, map}

  @type claims :: [claim]

  @type option ::
          {:time, integer}
          | {:ttl, integer}

  @type options :: [option]

  @type compact :: binary

  @doc """
  Creates a new `Authex.Token` struct from the given claims and options.

  ## Options
    * `:time` - the base time (timestamp format) in which to use.
    * `:ttl` - the TTL for the token.

  ## Examples

      Authex.Token.new(MyApp.Auth, [sub: 1], [ttl: 60])
  """
  def new(auth, claims \\ [], opts \\ []) do
    claims = build_claims(auth, claims)
    opts = build_options(auth, opts)

    %Token{}
    |> put_iat(opts.time)
    |> put_nbf(opts.time)
    |> put_exp(opts.time, opts.ttl)
    |> put_jti(claims.jti)
    |> put_sub(claims.sub)
    |> put_aud(claims.aud)
    |> put_iss(claims.iss)
    |> put_scopes(claims.scopes)
    |> put_meta(claims.meta)
  end

  @doc false
  def from_map(claims) when is_map(claims) do
    claims =
      Enum.reduce(claims, %{}, fn {key, val}, acc ->
        Map.put(acc, String.to_atom(key), val)
      end)

    struct(__MODULE__, claims)
  end

  @doc false
  def get_claims(token) do
    token
    |> Map.from_struct()
    |> Map.to_list()
    |> Enum.map(fn {key, val} -> {Atom.to_string(key), val} end)
    |> Enum.reject(fn {_, val} -> val == nil end)
    |> Map.new()
  end

  @doc false
  def put_nbf(token, time) do
    %{token | nbf: time - 1}
  end

  @doc false
  def put_iat(token, time) do
    %{token | iat: time}
  end

  @doc false
  def put_exp(token, time, ttl) do
    %{token | exp: time + ttl}
  end

  @doc false
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
  def put_sub(token, sub) do
    %{token | sub: sub}
  end

  @doc false
  def put_iss(token, iss) do
    %{token | iss: iss}
  end

  @doc false
  def put_aud(token, aud) do
    %{token | aud: aud}
  end

  @doc false
  def put_scopes(token, scopes) do
    %{token | scopes: scopes}
  end

  @doc false
  def put_meta(token, meta) do
    %{token | meta: meta}
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

  defp build_claims(auth, claims) do
    Enum.into(claims, %{
      jti: auth.config(:default_jti, {Authex.UUID, :generate, []}),
      scopes: auth.config(:default_scopes, []),
      sub: auth.config(:default_sub),
      aud: auth.config(:default_aud),
      iss: auth.config(:default_iss),
      meta: auth.config(:default_meta, %{})
    })
  end

  defp build_options(auth, opts) do
    Enum.into(opts, %{
      ttl: auth.config(:default_ttl, 3600),
      time: :os.system_time(:seconds)
    })
  end
end
