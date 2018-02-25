defmodule Serializer.Test do
  use Authex.Serializer

  alias Authex.Token

  def handle_from_token(%Token{sub: sub, scopes: scopes} = _token) do
    %{id: sub, scopes: scopes}
  end

  def handle_for_token(%{id: id, scopes: scopes} = _resource) do
    Auth.Test.token(sub: id, scopes: scopes)
  end

  def handle_for_token(%{id: id}) do
    Auth.Test.token(sub: id)
  end
end
