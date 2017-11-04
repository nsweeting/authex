defmodule Authex.Config do
  @doc """
  Returns the secret key from the application config. If no secret is present
  in the config, it will fall back to the `AUTH_SECRET` env var. If that is also
  not present, a new random secret will be generated.
  """
  def secret do
    case get(:secret) do
      secret when is_binary(secret) -> secret
      nil ->
        case System.get_env("AUTH_SECRET") do
          secret when is_binary(secret) -> put_secret(secret)
          nil -> 
            {:ok, secret} = Authex.Secret.new()
            put_secret(secret)
        end
    end
  end

  @doc """
  Returns the blacklist module from the config.
  """
  def blacklist do
    get(:blacklist, false)
  end

  @doc """
  Returns the checker module from the config.
  """
  def checker do
    get(:checker, Authex.Checker.Default)
  end

  @doc """
  Returns the serializer module from the config.
  """
  def serializer do
    get(:serializer, Authex.Serializer.Basic)
  end

  @doc """
  Returns the unauthorized plug module from the config.
  """
  def unauthorized do
    get(:unauthorized, Authex.Plug.Unauthorized)
  end

  @doc """
  Returns the forbidden plug module from the config.
  """
  def forbidden do
    get(:forbidden, Authex.Plug.Forbidden)
  end

  @doc false
  def get(key, default \\ nil) do
    Application.get_env(:authex, key, default)
  end

  defp put_secret(secret) do
    Application.put_env(:authex, :secret, secret, persistent: true)
    secret
  end

  @doc false
  def options(_, opts \\ [])
  def options(:claims, opts) do
    [
      iss: get(:default_iss),
      aud: get(:default_aud),
      jti: get(:jti_mfa, {UUID, :uuid4, [:hex]}),
      scopes: get(:default_scopes, []),
    ] |> Keyword.merge(opts)
  end
  def options(:token, opts) do
    [
      ttl: get(:default_ttl, 3600),
    ] |> Keyword.merge(opts)
  end
  def options(:signer, opts) do
    [
      secret: secret(),
      alg:    default_alg()
    ] |> Keyword.merge(opts)
  end
  def options(:verification, opts) do
    [
      alg:       default_alg(),
      secret:    secret(),
      blacklist: blacklist()
    ] |> Keyword.merge(opts)
  end
  def options(:authentication, opts) do
    [
      unauthorized: unauthorized(),
      serializer:   serializer(),
    ] |> Keyword.merge(opts)
  end
  def options(:authorization, opts) do
    [
      forbidden: forbidden(),
      permits: []
    ] |> Keyword.merge(opts)
  end

  defp default_alg do
    get(:default_alg, :hs256)
  end
end
