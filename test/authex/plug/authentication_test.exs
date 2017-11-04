defmodule Authex.Plug.AuthenticationTest do
  use ExUnit.Case
  use Plug.Test

  alias Authex.Plug.Authentication

  test "init/1 sets the default options" do
    opts = Authentication.init([])
    assert Keyword.get(opts, :unauthorized) == Authex.Plug.Unauthorized
    assert Keyword.get(opts, :serializer) == Authex.Serializer.Basic
  end

  test "init/1 allows the unauthorized option to be set" do
    opts = Authentication.init([unauthorized: "test"])
    assert Keyword.get(opts, :unauthorized) == "test"
  end

  test "init/1 allows the serializer option to be set" do
    opts = Authentication.init([serializer: "test"])
    assert Keyword.get(opts, :serializer) == "test"
  end

  test "call/2 sets the conn status as 401 if no headers are present" do
    conn = conn(:get, "/foo")
    assert_unauthorized(conn)
  end

  test "call/2 sets the conn status as 401 if the header is present but has no value" do
    conn = conn(:get, "/foo") |> put_req_header("authorization", "")
    assert_unauthorized(conn)
  end

  test "call/2 sets the conn status as 401 if the header is present and has a bad value" do
    conn = conn(:get, "/foo") |> put_req_header("authorization", "bad value")
    assert_unauthorized(conn)
  end

  test "call/2 sets the conn status as 401 if the header is present and has bearer and bad value" do
    conn = conn(:get, "/foo") |> put_req_header("authorization", "Bearer bad value")
    assert_unauthorized(conn)
  end

  test "call/2 sets the conn status as 401 if the token is incorrectly signed" do
    compact = Authex.token() |> Authex.sign([secret: "secret"])
    conn = conn(:get, "/foo") |> put_req_header("authorization", "Bearer #{compact}")
    assert_unauthorized(conn)
  end

  test "call/2 lets the conn continue when the authorization is correct" do
    compact = Authex.token() |> Authex.sign()
    conn = conn(:get, "/foo") |> put_req_header("authorization", "Bearer #{compact}")
    opts = Authentication.init([])
    conn = Authentication.call(conn, opts)
    assert conn.status == nil
  end

  test "call/2 sets the private token and current_user when authorization is correct" do
    compact = Authex.token() |> Authex.sign()
    conn = conn(:get, "/foo") |> put_req_header("authorization", "Bearer #{compact}")
    opts = Authentication.init([])
    conn = Authentication.call(conn, opts)
    assert {:ok, %Authex.Token{}} = Map.fetch(conn.private, :authex_token)
    assert {:ok, %{id: nil, scopes: []}} = Authex.current_user(conn)
  end

  def assert_unauthorized(conn) do
    opts = Authentication.init([])
    conn = Authentication.call(conn, opts)
    
    assert conn.status == 401
    assert conn.halted
    assert conn.resp_body == "Not Authorized"
  end
end
