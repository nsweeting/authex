defmodule Authex.Plug.AuthorizationTest do
  use ExUnit.Case
  use Plug.Test

  alias Authex.Plug.{Authentication, Authorization}

  describe "init/1" do
    test "returns given options if they are provided" do
      assert Authorization.init(forbidden: Foo, permits: ["foo"]) == %{
               forbidden: Foo,
               permits: ["foo"]
             }
    end

    test "returns default options" do
      assert Authorization.init([]) == %{
               forbidden: Authex.Plug.Forbidden,
               permits: []
             }
    end
  end

  describe "call/2" do
    test "returns a plug with 403 status if permits dont match token scopes" do
      start_supervised(Auth)
      opts = Authorization.init(permits: ["foo"])
      conn = conn(:get, "/") |> authenticate()
      assert %{status: 403, state: :sent, halted: true} = Authorization.call(conn, opts)
    end

    test "returns a plug with 403 status if action doesnt match token scopes" do
      start_supervised(Auth)
      opts = Authorization.init(permits: ["foo"])
      conn = conn(:post, "/") |> authenticate(["foo/read"])
      assert %{status: 403, state: :sent, halted: true} = Authorization.call(conn, opts)
    end

    test "returns a plug with no modifications if permits match scopes for GET" do
      start_supervised(Auth)
      opts = Authorization.init(permits: ["foo"])
      conn = conn(:get, "/") |> authenticate(["foo/read"])
      assert %{status: nil, state: :unset, halted: false} = Authorization.call(conn, opts)
    end

    test "returns a plug with no modifications if permits match scopes for POST" do
      start_supervised(Auth)
      opts = Authorization.init(permits: ["foo"])
      conn = conn(:post, "/") |> authenticate(["foo/write"])
      assert %{status: nil, state: :unset, halted: false} = Authorization.call(conn, opts)
    end

    test "returns a plug with no modifications if permits match scopes for PUT" do
      start_supervised(Auth)
      opts = Authorization.init(permits: ["foo"])
      conn = conn(:put, "/") |> authenticate(["foo/write"])
      assert %{status: nil, state: :unset, halted: false} = Authorization.call(conn, opts)
    end

    test "returns a plug with no modifications if permits match scopes for PATCH" do
      start_supervised(Auth)
      opts = Authorization.init(permits: ["foo"])
      conn = conn(:patch, "/") |> authenticate(["foo/write"])
      assert %{status: nil, state: :unset, halted: false} = Authorization.call(conn, opts)
    end

    test "returns a plug with no modifications if permits match scopes for DELETE" do
      start_supervised(Auth)
      opts = Authorization.init(permits: ["foo"])
      conn = conn(:delete, "/") |> authenticate(["foo/delete"])
      assert %{status: nil, state: :unset, halted: false} = Authorization.call(conn, opts)
    end
  end

  defp authenticate(conn, scopes \\ []) do
    opts = Authentication.init(with: Auth)
    compact_token = Authex.compact_token(Auth, scopes: scopes)

    conn
    |> put_req_header("authorization", "Bearer #{compact_token}")
    |> Authentication.call(opts)
  end
end
