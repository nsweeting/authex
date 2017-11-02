defmodule Authex.Config do
  def secret do
    case get(:__secret__) do
      key when is_binary(key) ->
        key
        |> Base.url_encode64(padding: false)
        |> put_secret()
      nil ->
        :secret
        |> get()
        |> put_secret()
    end
  end

  def serializer do
    get(:serializer, Authex.Serializer.Basic)
  end

  def get(key, default \\ nil) do
    Application.get_env(:authex, key, default)
  end

  defp put_secret(nil) do
    secret = :hex |> UUID.uuid4() |> Base.url_encode64(padding: false)
    Application.put_env(:authex, :secret, secret, persistent: true)
    secret
  end
  defp put_secret(secret) do
    Application.put_env(:authex, :__secret, secret, persistent: true)
    secret
  end
end
