defmodule Authex.SerializerTest do
  use ExUnit.Case
  doctest Authex.Serializer

  alias Authex.Serializer
  alias Authex.Serializer.Basic

  test "for_token/1 uses the default serializer" do
    resource = %{id: 1, scopes: ["test/read"]}
    token = Serializer.for_token(resource)
    assert token.sub == 1
    assert token.scopes == ["test/read"]
  end

  test "for_token/2 uses the serializer that is passed to it" do
    resource = %{id: 1, scopes: ["test/read"]}
    token = Serializer.for_token(Basic, resource)
    assert token.sub == 1
    assert token.scopes == ["test/read"]
  end

  test "from_token/1 uses the default serializer" do
    token = Authex.token([sub: 1, scopes: ["test/read"]])
    resource = Serializer.from_token(token)
    assert resource == %{id: 1, scopes: ["test/read"]}
  end

  test "from_token/2 uses the serializer that is passed to it" do
    token = Authex.token([sub: 1, scopes: ["test/read"]])
    resource = Serializer.from_token(Basic, token)
    assert resource == %{id: 1, scopes: ["test/read"]}
  end

  test "for_compact_token/1 uses the default serializer" do
    resource = %{id: 1, scopes: ["test/read"]}
    compact_token = Serializer.for_compact_token(resource)
    assert is_binary(compact_token)
  end

  test "for_compact_token/2 uses the serializer that is passed to it" do
    resource = %{id: 1, scopes: ["test/read"]}
    compact_token = Serializer.for_compact_token(Basic, resource)
    assert is_binary(compact_token)
  end
end
