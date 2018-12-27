defmodule Authex.AuthenticationPlugTest do
  use ExUnit.Case
  use Plug.Test

  import Authex.TestHelpers
  import Plug.Conn, only: [put_req_header: 3]

  alias Authex.AuthenticationPlug

  setup_all do
    Auth.start_link()
    :ok
  end

  setup do
    reset_config()
  end

  describe "opts/1" do
    test "returns default options if non are provided" do
      assert AuthenticationPlug.init(auth: Auth) == %{
               auth: Auth,
               unauthorized: Authex.UnauthorizedPlug
             }
    end

    test "returns given options if they are provided" do
      assert AuthenticationPlug.init(auth: Auth, unauthorized: Other) == %{
               auth: Auth,
               unauthorized: Other
             }
    end

    test "returns config options if they are present" do
      save_config(unauthorized: Other)

      assert AuthenticationPlug.init(auth: Auth) == %{
               auth: Auth,
               unauthorized: Other
             }
    end

    test "raises if the auth module is not present" do
      assert_raise Authex.Error, "auth module missing", fn ->
        AuthenticationPlug.init()
      end
    end
  end

  describe "call/2" do
    test "returns a plug with 401 status if authorization is empty" do
      opts = AuthenticationPlug.init(auth: Auth)
      conn = conn(:get, "/")
      assert %{status: 401, state: :sent, halted: true} = AuthenticationPlug.call(conn, opts)
    end

    test "returns a plug with 401 status if authorization is invalid" do
      save_config(secret: "foo")
      opts = AuthenticationPlug.init(auth: Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer bad_token")
      assert %{status: 401, state: :sent, halted: true} = AuthenticationPlug.call(conn, opts)
    end

    test "returns a plug with 401 status if authorization is expired" do
      save_config(secret: "foo")
      compact_token = Auth.token([], ttl: -1) |> Auth.sign()
      opts = AuthenticationPlug.init(auth: Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer #{compact_token}")
      assert %{status: 401, state: :sent, halted: true} = AuthenticationPlug.call(conn, opts)
    end

    test "returns a plug with 401 status if jti is blacklisted" do
      {:ok, pid} = Mocklist.start_link()
      save_config(secret: "foo", blacklist: Mocklist)
      token = Auth.token()
      Auth.blacklist(token)
      compact_token = Auth.sign(token)
      opts = AuthenticationPlug.init(auth: Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer #{compact_token}")
      assert %{status: 401, state: :sent, halted: true} = AuthenticationPlug.call(conn, opts)
      Process.exit(pid, :kill)
    end

    test "returns a plug with 401 status if sub is banned" do
      {:ok, pid} = Mocklist.start_link()
      save_config(secret: "foo", banlist: Mocklist)
      token = Auth.token()
      Auth.ban(token)
      compact_token = Auth.sign(token)
      opts = AuthenticationPlug.init(auth: Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer #{compact_token}")
      assert %{status: 401, state: :sent, halted: true} = AuthenticationPlug.call(conn, opts)
      Process.exit(pid, :kill)
    end

    test "returns a plug with no modifications if authorization is valid" do
      save_config(secret: "foo", serializer: Serializer)
      compact_token = Auth.token() |> Auth.sign()
      opts = AuthenticationPlug.init(auth: Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer #{compact_token}")
      assert %{status: nil, state: :unset, halted: false} = AuthenticationPlug.call(conn, opts)
    end

    test "sets the current user private key" do
      save_config(secret: "foo", serializer: Serializer)
      compact_token = Auth.token() |> Auth.sign()
      opts = AuthenticationPlug.init(auth: Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer #{compact_token}")
      conn = AuthenticationPlug.call(conn, opts)
      assert {:ok, %{id: nil, scopes: []}} = Auth.current_user(conn)
    end

    test "sets the token private key" do
      save_config(secret: "foo", serializer: Serializer)
      compact_token = Auth.token() |> Auth.sign()
      opts = AuthenticationPlug.init(auth: Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer #{compact_token}")
      conn = AuthenticationPlug.call(conn, opts)
      assert {:ok, []} = Auth.current_scopes(conn)
    end
  end
end
