defmodule Authex.Serializer.Basic do
  use Authex.Serializer

  alias Authex.Token

  def handle_from_token(%Token{sub: sub, scopes: scopes} = _token) do
    %{id: sub, scopes: scopes}
  end

  def handle_for_token(%{id: id, scopes: scopes} = _resource) do
    Token.new([sub: id, scopes: scopes])
  end
  def handle_for_token(%{id: id}) do
    Token.new([sub: id])
  end
end
