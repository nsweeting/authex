defmodule Authex.AuthorizationPlugTest do
  use ExUnit.Case
  use Plug.Test

  import Authex.TestHelpers

  alias Authex.AuthenticationPlug
  alias Authex.AuthorizationPlug

  setup_all do
    Auth.start_link()
    :ok
  end

  setup do
    reset_config()
  end

  describe "opts/1" do
    test "returns default options if non are provided" do
      assert AuthorizationPlug.init(auth: Auth) == %{
               auth: Auth,
               forbidden: Authex.ForbiddenPlug,
               permits: []
             }
    end

    test "returns given options if they are provided" do
      assert AuthorizationPlug.init(auth: Auth, forbidden: Other, permits: ["foo"]) == %{
               auth: Auth,
               forbidden: Other,
               permits: ["foo"]
             }
    end

    test "returns config options if they are present" do
      save_config(forbidden: Other)

      assert AuthorizationPlug.init(auth: Auth) == %{
               auth: Auth,
               forbidden: Other,
               permits: []
             }
    end

    test "raises if the auth module is not present" do
      assert_raise Authex.Error, "auth module missing", fn ->
        AuthorizationPlug.init()
      end
    end
  end

  describe "call/2" do
    test "returns a plug with 403 status if permits dont match token scopes" do
      opts = AuthorizationPlug.init(auth: Auth, permits: ["foo"])
      conn = conn(:get, "/") |> authenticate()
      assert %{status: 403, state: :sent, halted: true} = AuthorizationPlug.call(conn, opts)
    end

    test "returns a plug with 403 status if action doesnt match token scopes" do
      opts = AuthorizationPlug.init(auth: Auth, permits: ["foo"])
      conn = conn(:post, "/") |> authenticate(["foo/read"])
      assert %{status: 403, state: :sent, halted: true} = AuthorizationPlug.call(conn, opts)
    end

    test "returns a plug with no modifications if permits match scopes for GET" do
      opts = AuthorizationPlug.init(auth: Auth, permits: ["foo"])
      conn = conn(:get, "/") |> authenticate(["foo/read"])
      assert %{status: nil, state: :unset, halted: false} = AuthorizationPlug.call(conn, opts)
    end

    test "returns a plug with no modifications if permits match scopes for POST" do
      opts = AuthorizationPlug.init(auth: Auth, permits: ["foo"])
      conn = conn(:post, "/") |> authenticate(["foo/write"])
      assert %{status: nil, state: :unset, halted: false} = AuthorizationPlug.call(conn, opts)
    end

    test "returns a plug with no modifications if permits match scopes for PUT" do
      opts = AuthorizationPlug.init(auth: Auth, permits: ["foo"])
      conn = conn(:put, "/") |> authenticate(["foo/write"])
      assert %{status: nil, state: :unset, halted: false} = AuthorizationPlug.call(conn, opts)
    end

    test "returns a plug with no modifications if permits match scopes for PATCH" do
      opts = AuthorizationPlug.init(auth: Auth, permits: ["foo"])
      conn = conn(:patch, "/") |> authenticate(["foo/write"])
      assert %{status: nil, state: :unset, halted: false} = AuthorizationPlug.call(conn, opts)
    end

    test "returns a plug with no modifications if permits match scopes for DELETE" do
      opts = AuthorizationPlug.init(auth: Auth, permits: ["foo"])
      conn = conn(:delete, "/") |> authenticate(["foo/delete"])
      assert %{status: nil, state: :unset, halted: false} = AuthorizationPlug.call(conn, opts)
    end
  end

  defp authenticate(conn, scopes \\ []) do
    save_config(secret: "foo", serializer: Serializer)
    opts = AuthenticationPlug.init(auth: Auth)
    compact_token = Auth.token(scopes: scopes) |> Auth.sign()

    conn
    |> put_req_header("authorization", "Bearer #{compact_token}")
    |> AuthenticationPlug.call(opts)
  end
end
