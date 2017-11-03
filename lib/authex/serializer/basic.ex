defmodule Authex.Serializer.Basic do
  use Authex.Serializer

  alias Authex.Token

  def handle_from_token(%Token{sub: sub, scopes: scopes}) do
    %{id: sub, scopes: scopes}
  end

  def handle_for_token(%{id: id, scopes: scopes}) do
    Token.new([sub: id, scopes: scopes])
  end
  def handle_for_token(%{id: id}) do
    Token.new([sub: id])
  end
end
