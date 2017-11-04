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

  @doc false
  def blacklist do
    get(:blacklist, false)
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

  @doc """
  Returns the default alg used for signing and verifying tokens from the config.
  """
  def default_alg do
    get(:default_alg, :hs256)
  end

  @doc """
  Returns the default iss claim used in tokens from the config.
  """
  def default_iss do
    get(:default_iss)
  end

  @doc """
  Returns the default aud claim used in tokens from the config.
  """
  def default_aud do
    get(:default_aud)
  end

  @doc """
  Returns the default time to live for tokens from the config.
  """
  def default_ttl do
    get(:default_ttl, 3600)
  end

  @doc """
  Returns the default scopes for tokens from the config.
  """
  def default_scopes do
    get(:default_scopes, [])
  end

  @doc """
  Returns the {module, function, args} used to generate the jti claim in 
  tokens from the config..
  """
  def jti_mfa do
    get(:jti_mfa, {UUID, :uuid4, [:hex]})
  end

  @doc false
  def get(key, default \\ nil) do
    Application.get_env(:authex, key, default)
  end

  defp put_secret(secret) do
    Application.put_env(:authex, :secret, secret, persistent: true)
    secret
  end
end
