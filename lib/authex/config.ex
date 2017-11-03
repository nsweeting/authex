defmodule Authex.Config do
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

  def blacklist do
    get(:blacklist, false)
  end

  def serializer do
    get(:serializer, Authex.Serializer.Basic)
  end

  def unauthorized do
    get(:unauthorized, Authex.Plug.Unauthorized)
  end

  def forbidden do
    get(:forbidden, Authex.Plug.Forbidden)
  end

  def default_alg do
    get(:default_alg, :hs256)
  end

  def default_iss do
    get(:default_iss)
  end

  def default_aud do
    get(:default_aud)
  end

  def default_ttl do
    get(:default_ttl, 3600)
  end

  def default_scopes do
    get(:default_scopes, [])
  end

  def jti_mfa do
    get(:jti_mfa, {UUID, :uuid4, [:hex]})
  end

  def get(key, default \\ nil) do
    Application.get_env(:authex, key, default)
  end

  defp put_secret(secret) do
    Application.put_env(:authex, :secret, secret, persistent: true)
    secret
  end
end
