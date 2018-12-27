defmodule Serializer do
  use Authex.Serializer

  alias Authex.Token

  @impl Authex.Serializer
  def from_token(%Token{sub: sub, scopes: scopes}, _opts) do
    {:ok, %{id: sub, scopes: scopes}}
  end

  @impl Authex.Serializer
  def for_token(%{id: id, scopes: scopes}, _opts) do
    {:ok, Auth.token(sub: id, scopes: scopes)}
  end

  def for_token(%{id: id}, _opts) do
    {:ok, Auth.token(sub: id)}
  end
end
