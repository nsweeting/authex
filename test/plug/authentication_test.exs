defmodule Authex.Plug.AuthenticationTest do
  use ExUnit.Case
  use Plug.Test

  import Plug.Conn, only: [put_req_header: 3]

  alias Authex.Plug.Authentication

  describe "init/1" do
    test "returns given options if they are provided" do
      assert Authentication.init(with: Foo, unauthorized: Bar, header: "foo") == %{
               header: "foo",
               unauthorized: Bar,
               with: Foo
             }
    end

    test "raises if the auth module is not present" do
      assert_raise Authex.Error,
                   "Auth module missing. Please pass an auth module using the :with key.",
                   fn ->
                     Authentication.init()
                   end
    end
  end

  describe "call/2" do
    test "returns a plug with 401 status if authorization is empty" do
      start_supervised(Auth)
      opts = Authentication.init(with: Auth)
      conn = conn(:get, "/")
      assert %{status: 401, state: :sent, halted: true} = Authentication.call(conn, opts)
    end

    test "returns a plug with 401 status if authorization is invalid" do
      start_supervised(Auth)
      opts = Authentication.init(with: Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer bad_token")
      assert %{status: 401, state: :sent, halted: true} = Authentication.call(conn, opts)
    end

    test "returns a plug with 401 status if authorization is expired" do
      start_supervised(Auth)
      compact_token = Authex.compact_token(Auth, [], ttl: -1)
      opts = Authentication.init(with: Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer #{compact_token}")
      assert %{status: 401, state: :sent, halted: true} = Authentication.call(conn, opts)
    end

    test "returns a plug with 401 status if jti is blacklisted" do
      start_supervised({Auth, [blacklist: Mocklist]})
      start_supervised(Mocklist)
      token = Authex.token(Auth)
      Authex.blacklist(Auth, token)
      compact_token = Authex.sign(Auth, token)
      opts = Authentication.init(with: Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer #{compact_token}")
      assert %{status: 401, state: :sent, halted: true} = Authentication.call(conn, opts)
    end

    test "returns a plug with no modifications if authorization is valid" do
      start_supervised(Auth)
      compact_token = Authex.compact_token(Auth)
      opts = Authentication.init(with: Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer #{compact_token}")
      assert %{status: nil, state: :unset, halted: false} = Authentication.call(conn, opts)
    end

    test "sets the :authex_resource private key" do
      start_supervised(Auth)
      compact_token = Authex.compact_token(Auth)
      opts = Authentication.init(with: Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer #{compact_token}")
      conn = Authentication.call(conn, opts)
      assert {:ok, %{id: nil, scopes: []}} = Authex.current_resource(conn)
    end

    test "sets the :authex_token private key" do
      start_supervised(Auth)
      compact_token = Authex.compact_token(Auth)
      opts = Authentication.init(with: Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer #{compact_token}")
      conn = Authentication.call(conn, opts)
      assert {:ok, %Authex.Token{}} = Authex.current_token(conn)
    end
  end
end
