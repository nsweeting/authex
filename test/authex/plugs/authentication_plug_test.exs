defmodule Authex.AuthenticationPlugTest do
  use ExUnit.Case
  use Plug.Test

  import Authex.TestHelpers
  import Plug.Conn, only: [put_req_header: 3]

  alias Auth.Test, as: Auth
  alias Authex.AuthenticationPlug

  setup do
    reset_config()
  end

  describe "opts/1" do
    test "returns default options if non are provided" do
      assert AuthenticationPlug.init(Auth) == %{
               module: Auth,
               unauthorized: Authex.UnauthorizedPlug
             }
    end

    test "returns given options if they are provided" do
      assert AuthenticationPlug.init({Auth, unauthorized: Other}) == %{
               module: Auth,
               unauthorized: Other
             }
    end

    test "returns config options if they are present" do
      set_config(unauthorized: Other)

      assert AuthenticationPlug.init(Auth) == %{
               module: Auth,
               unauthorized: Other
             }
    end
  end

  describe "call/2" do
    test "returns a plug with 401 status if authorization is empty" do
      opts = AuthenticationPlug.init(Auth)
      conn = conn(:get, "/")
      assert %{status: 401, state: :sent, halted: true} = AuthenticationPlug.call(conn, opts)
    end

    test "returns a plug with 401 status if authorization is invalid" do
      set_config(secret: "foo")
      opts = AuthenticationPlug.init(Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer bad_token")
      assert %{status: 401, state: :sent, halted: true} = AuthenticationPlug.call(conn, opts)
    end

    test "returns a plug with 401 status if authorization is expired" do
      set_config(secret: "foo")
      compact_token = Auth.token([], ttl: -1) |> Auth.sign()
      opts = AuthenticationPlug.init(Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer #{compact_token}")
      assert %{status: 401, state: :sent, halted: true} = AuthenticationPlug.call(conn, opts)
    end

    test "returns a plug with 401 status if jti is blacklisted" do
      {:ok, pid} = Blacklist.Test.start_link()
      set_config(secret: "foo", blacklist: Blacklist.Test)
      token = Auth.token()
      Auth.blacklist(token)
      compact_token = Auth.sign(token)
      opts = AuthenticationPlug.init(Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer #{compact_token}")
      assert %{status: 401, state: :sent, halted: true} = AuthenticationPlug.call(conn, opts)
      Process.exit(pid, :kill)
    end

    test "returns a plug with 401 status if sub is banned" do
      {:ok, pid} = Banlist.Test.start_link()
      set_config(secret: "foo", banlist: Banlist.Test)
      token = Auth.token()
      Auth.ban(token)
      compact_token = Auth.sign(token)
      opts = AuthenticationPlug.init(Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer #{compact_token}")
      assert %{status: 401, state: :sent, halted: true} = AuthenticationPlug.call(conn, opts)
      Process.exit(pid, :kill)
    end

    test "returns a plug with no modifications if authorization is valid" do
      set_config(secret: "foo", serializer: Serializer.Test)
      compact_token = Auth.token() |> Auth.sign()
      opts = AuthenticationPlug.init(Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer #{compact_token}")
      assert %{status: nil, state: :unset, halted: false} = AuthenticationPlug.call(conn, opts)
    end

    test "sets the current user private key" do
      set_config(secret: "foo", serializer: Serializer.Test)
      compact_token = Auth.token() |> Auth.sign()
      opts = AuthenticationPlug.init(Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer #{compact_token}")
      conn = AuthenticationPlug.call(conn, opts)
      assert {:ok, %{id: nil, scopes: []}} = Auth.current_user(conn)
    end

    test "sets the token private key" do
      set_config(secret: "foo", serializer: Serializer.Test)
      compact_token = Auth.token() |> Auth.sign()
      opts = AuthenticationPlug.init(Auth)
      conn = conn(:get, "/") |> put_req_header("authorization", "Bearer #{compact_token}")
      conn = AuthenticationPlug.call(conn, opts)
      assert {:ok, []} = Auth.current_scopes(conn)
    end
  end
end
