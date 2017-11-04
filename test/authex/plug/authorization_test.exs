defmodule Authex.Plug.AuthorizationTest do
  use ExUnit.Case
  use Plug.Test

  alias Authex.Plug.Authorization

  test "init/1 sets the default options" do
    opts = Authorization.init([])
    assert Keyword.get(opts, :forbidden) == Authex.Plug.Forbidden
    assert Keyword.get(opts, :permits) == []
  end

  test "init/1 allows the unauthorized option to be set" do
    opts = Authorization.init([forbidden: "foo"])
    assert Keyword.get(opts, :forbidden) == "foo"
  end

  test "init/1 allows the permits option to be set" do
    opts = Authorization.init([permits: "foo"])
    assert Keyword.get(opts, :permits) == "foo"
  end

  test "call/2 sets the conn status as 403 if the token has no scopes" do
    token = Authex.token()
    conn = conn(:get, "/foo") |> put_private(:authex_token, token)
    assert_forbidden(conn, permits: ["foo"])
  end

  test "call/2 sets the conn status as 403 if the token has different scopes" do
    token = Authex.token(scopes: ["foo"])
    conn = conn(:get, "/foo") |> put_private(:authex_token, token)
    assert_forbidden(conn, permits: ["bar"])
  end

  test "call/2 sets the conn status as 403 if the token scope is nil" do
    token = Authex.token(scopes: nil)
    conn = conn(:get, "/foo") |> put_private(:authex_token, token)
    assert_forbidden(conn, permits: ["bar"])
  end

  test "call/2 lets the conn continue if the token scope is of the read type with a GET request" do
    token = Authex.token(scopes: ["foo/read"])
    conn = conn(:get, "/foo") |> put_private(:authex_token, token)
    assert_continue(conn, permits: ["foo"])
  end

  test "call/2 lets the conn continue if the token scope is of the read type with a HEAD request" do
    token = Authex.token(scopes: ["foo/read"])
    conn = conn(:head, "/foo") |> put_private(:authex_token, token)
    assert_continue(conn, permits: ["foo", "bar"])
  end

  test "call/2 lets the conn continue if the token scope is of the write type with a POST request" do
    token = Authex.token(scopes: ["foo/write"])
    conn = conn(:post, "/foo") |> put_private(:authex_token, token)
    assert_continue(conn, permits: ["foo"])
  end

  test "call/2 lets the conn continue if the token scope is of the write type with a PUT request" do
    token = Authex.token(scopes: ["foo/write"])
    conn = conn(:post, "/foo") |> put_private(:authex_token, token)
    assert_continue(conn, permits: ["foo"])
  end

  test "call/2 lets the conn continue if the token scope is of the write type with a PATCH request" do
    token = Authex.token(scopes: ["foo/write"])
    conn = conn(:patch, "/foo") |> put_private(:authex_token, token)
    assert_continue(conn, permits: ["foo"])
  end

  test "call/2 lets the conn continue if the token scope is of the write type with a DELETE request" do
    token = Authex.token(scopes: ["foo/delete"])
    conn = conn(:delete, "/foo") |> put_private(:authex_token, token)
    assert_continue(conn, permits: ["foo"])
  end

  def assert_forbidden(conn, opts) do
    opts = Authorization.init(opts)
    conn = Authorization.call(conn, opts)
    
    assert conn.status == 403
    assert conn.halted
    assert conn.resp_body == "Forbidden"
  end

  def assert_continue(conn, opts) do
    opts = Authorization.init(opts)
    conn = Authorization.call(conn, opts)
    
    assert conn.status == nil
  end
end
