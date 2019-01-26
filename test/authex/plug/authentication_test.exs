defmodule Authex.Plug.AuthenticationTest do
  use ExUnit.Case
  use Plug.Test

  import Authex.TestHelpers
  import Plug.Conn, only: [put_req_header: 3]

  alias Authex.Plug.Authentication

  setup_all do
    Auth.start_link()
    :ok
  end

  setup do
    reset_config()
  end

  describe "init/1" do
    test "returns given options if they are provided" do
      assert Authentication.init(with: Auth) == [with: Auth]
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
      opts = Authentication.init(with: Auth)
      conn = conn(:get, "/")
      assert %{status: 401, state: :sent, halted: true} = Authentication.call(conn, opts)
    end

    test "returns a plug with 401 status if authorization is invalid" do
      save_config(secret: "foo")
      opts = Authentication.init(with: Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer bad_token")
      assert %{status: 401, state: :sent, halted: true} = Authentication.call(conn, opts)
    end

    test "returns a plug with 401 status if authorization is expired" do
      save_config(secret: "foo")
      compact_token = Auth.token([], ttl: -1) |> Auth.sign()
      opts = Authentication.init(with: Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer #{compact_token}")
      assert %{status: 401, state: :sent, halted: true} = Authentication.call(conn, opts)
    end

    test "returns a plug with 401 status if jti is blacklisted" do
      {:ok, pid} = Mocklist.start_link()
      save_config(secret: "foo", blacklist: Mocklist)
      token = Auth.token()
      Auth.blacklist(token)
      compact_token = Auth.sign(token)
      opts = Authentication.init(with: Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer #{compact_token}")
      assert %{status: 401, state: :sent, halted: true} = Authentication.call(conn, opts)
      Process.exit(pid, :kill)
    end

    test "returns a plug with no modifications if authorization is valid" do
      save_config(secret: "foo", serializer: Serializer)
      compact_token = Auth.token() |> Auth.sign()
      opts = Authentication.init(with: Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer #{compact_token}")
      assert %{status: nil, state: :unset, halted: false} = Authentication.call(conn, opts)
    end

    test "sets the :authex_current_user private key" do
      save_config(secret: "foo", serializer: Serializer)
      compact_token = Auth.token() |> Auth.sign()
      opts = Authentication.init(with: Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer #{compact_token}")
      conn = Authentication.call(conn, opts)
      assert {:ok, %{id: nil, scopes: []}} = Auth.current_user(conn)
    end

    test "sets the :authex_token private key" do
      save_config(secret: "foo", serializer: Serializer)
      compact_token = Auth.token() |> Auth.sign()
      opts = Authentication.init(with: Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer #{compact_token}")
      conn = Authentication.call(conn, opts)
      assert {:ok, %Authex.Token{}} = Auth.current_token(conn)
    end
  end
end
