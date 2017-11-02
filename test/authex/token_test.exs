defmodule Authex.TokenTest do
  use ExUnit.Case

  alias Authex.Token

  test "new/2 can create a token with iss claim" do
    token = Token.new(iss: "test")
    assert token.iss == "test"
  end

  test "new/2 can create a token with aud claim" do
    token = Token.new(aud: "test")
    assert token.aud == "test"
  end

  test "new/2 can create a token with sub claim" do
    token = Token.new(sub: 1)
    assert token.sub == 1
  end

  test "new/2 can create a token with scopes claim" do
    token = Token.new(scopes: ["test"])
    assert token.scopes == ["test"]
  end

  test "new/2 automatically generates jti claim" do
    token = Token.new()
    assert String.length(token.jti) > 10
  end

  test "new/2 token scopes default to an empty list" do
    token = Token.new()
    assert token.scopes == []
  end

  test "new/2 token exp defaults to time + 1 hour" do
    token = Token.new([], [time: 0])
    assert token.exp == 3600
  end

  test "new/2 token nbf defaults to time - 1 second" do
    token = Token.new([], [time: 0])
    assert token.nbf == -1
  end

  test "new/2 allows the current time to be set through options" do
    token = Token.new([], [time: 0])
    assert token.iat == 0
  end

  test "new/2 token iat defaults to current time" do
    time = :os.system_time(:seconds)
    token = Token.new()
    assert token.iat <= time
    assert token.iat > (time - 5)
  end

  test "from_map/1 creates tokens from binary claim maps" do
    claims = %{"iss" => "test", "exp" => 1, "nbf" => 1, "sub" => 1}
    token = Token.from_map(claims)
    assert token.iss == "test"
    assert token.exp == 1
    assert token.nbf == 1
    assert token.sub == 1
  end

  test "from_map/1 creates tokens from binary claim maps that have extra attributes" do
    claims = %{"extra" => "extra"}
    token = Token.from_map(claims)
    assert token.iss == nil
    assert_raise(KeyError, fn -> token.extra end)
  end

  test "has_scope?/2 compares token scopes to allowed scopes and returns false or the first scope found" do
    token = Token.new([scopes: ["page/read"]])
    assert Token.has_scope?(token, []) == false
    assert Token.has_scope?(token, ["page/write"]) == false
    assert Token.has_scope?(token, "string") == false
    assert Token.has_scope?(token, [1]) == false
    assert Token.has_scope?(token, ["page/write", "page/delete"]) == false
    assert Token.has_scope?(token, ["page/delete", "page/read"]) == "page/read"
    assert Token.has_scope?(token, ["page/read"]) == "page/read"
  end
end
