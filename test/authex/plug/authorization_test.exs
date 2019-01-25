defmodule Authex.AuthorizationPlugTest do
  use ExUnit.Case
  use Plug.Test

  import Authex.TestHelpers

  alias Authex.Plug.Authentication
  alias Authex.Plug.Authorization

  setup_all do
    Auth.start_link()
    :ok
  end

  setup do
    reset_config()
  end

  describe "init/1" do
    test "returns given options if they are provided" do
      assert Authorization.init(with: Auth) == [with: Auth]
    end

    test "raises if the auth module is not present" do
      assert_raise Authex.Error, "auth module missing", fn ->
        Authorization.init()
      end
    end
  end

  describe "call/2" do
    test "returns a plug with 403 status if permits dont match token scopes" do
      opts = Authorization.init(with: Auth, permits: ["foo"])
      conn = conn(:get, "/") |> authenticate()
      assert %{status: 403, state: :sent, halted: true} = Authorization.call(conn, opts)
    end

    test "returns a plug with 403 status if action doesnt match token scopes" do
      opts = Authorization.init(with: Auth, permits: ["foo"])
      conn = conn(:post, "/") |> authenticate(["foo/read"])
      assert %{status: 403, state: :sent, halted: true} = Authorization.call(conn, opts)
    end

    test "returns a plug with no modifications if permits match scopes for GET" do
      opts = Authorization.init(with: Auth, permits: ["foo"])
      conn = conn(:get, "/") |> authenticate(["foo/read"])
      assert %{status: nil, state: :unset, halted: false} = Authorization.call(conn, opts)
    end

    test "returns a plug with no modifications if permits match scopes for POST" do
      opts = Authorization.init(with: Auth, permits: ["foo"])
      conn = conn(:post, "/") |> authenticate(["foo/write"])
      assert %{status: nil, state: :unset, halted: false} = Authorization.call(conn, opts)
    end

    test "returns a plug with no modifications if permits match scopes for PUT" do
      opts = Authorization.init(with: Auth, permits: ["foo"])
      conn = conn(:put, "/") |> authenticate(["foo/write"])
      assert %{status: nil, state: :unset, halted: false} = Authorization.call(conn, opts)
    end

    test "returns a plug with no modifications if permits match scopes for PATCH" do
      opts = Authorization.init(with: Auth, permits: ["foo"])
      conn = conn(:patch, "/") |> authenticate(["foo/write"])
      assert %{status: nil, state: :unset, halted: false} = Authorization.call(conn, opts)
    end

    test "returns a plug with no modifications if permits match scopes for DELETE" do
      opts = Authorization.init(with: Auth, permits: ["foo"])
      conn = conn(:delete, "/") |> authenticate(["foo/delete"])
      assert %{status: nil, state: :unset, halted: false} = Authorization.call(conn, opts)
    end
  end

  defp authenticate(conn, scopes \\ []) do
    save_config(secret: "foo", serializer: Serializer)
    opts = Authentication.init(with: Auth)
    compact_token = Auth.token(scopes: scopes) |> Auth.sign()

    conn
    |> put_req_header("authorization", "Bearer #{compact_token}")
    |> Authentication.call(opts)
  end
end
