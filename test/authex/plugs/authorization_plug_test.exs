defmodule Authex.AuthorizationPlugTest do
  use ExUnit.Case
  use Plug.Test

  import Authex.TestHelpers

  alias Auth.Test, as: Auth
  alias Authex.AuthenticationPlug
  alias Authex.AuthorizationPlug

  setup do
    reset_config()
  end

  describe "opts/1" do
    test "returns default options if non are provided" do
      assert AuthorizationPlug.init(Auth) == %{
               module: Auth,
               forbidden: Authex.ForbiddenPlug,
               permits: []
             }
    end

    test "returns given options if they are provided" do
      assert AuthorizationPlug.init({Auth, forbidden: Other, permits: ["foo"]}) == %{
               module: Auth,
               forbidden: Other,
               permits: ["foo"]
             }
    end

    test "returns config options if they are present" do
      set_config(forbidden: Other)

      assert AuthorizationPlug.init(Auth) == %{
               module: Auth,
               forbidden: Other,
               permits: []
             }
    end
  end

  describe "call/2" do
    test "returns a plug with 403 status if permits dont match token scopes" do
      opts = AuthorizationPlug.init({Auth, permits: ["foo"]})
      conn = conn(:get, "/") |> authenticate()
      assert %{status: 403, state: :sent, halted: true} = AuthorizationPlug.call(conn, opts)
    end

    test "returns a plug with 403 status if action doesnt match token scopes" do
      opts = AuthorizationPlug.init({Auth, permits: ["foo"]})
      conn = conn(:post, "/") |> authenticate(["foo/read"])
      assert %{status: 403, state: :sent, halted: true} = AuthorizationPlug.call(conn, opts)
    end

    test "returns a plug with no modifications if permits match scopes for GET" do
      opts = AuthorizationPlug.init({Auth, permits: ["foo"]})
      conn = conn(:get, "/") |> authenticate(["foo/read"])
      assert %{status: nil, state: :unset, halted: false} = AuthorizationPlug.call(conn, opts)
    end

    test "returns a plug with no modifications if permits match scopes for POST" do
      opts = AuthorizationPlug.init({Auth, permits: ["foo"]})
      conn = conn(:post, "/") |> authenticate(["foo/write"])
      assert %{status: nil, state: :unset, halted: false} = AuthorizationPlug.call(conn, opts)
    end

    test "returns a plug with no modifications if permits match scopes for PUT" do
      opts = AuthorizationPlug.init({Auth, permits: ["foo"]})
      conn = conn(:put, "/") |> authenticate(["foo/write"])
      assert %{status: nil, state: :unset, halted: false} = AuthorizationPlug.call(conn, opts)
    end

    test "returns a plug with no modifications if permits match scopes for PATCH" do
      opts = AuthorizationPlug.init({Auth, permits: ["foo"]})
      conn = conn(:patch, "/") |> authenticate(["foo/write"])
      assert %{status: nil, state: :unset, halted: false} = AuthorizationPlug.call(conn, opts)
    end

    test "returns a plug with no modifications if permits match scopes for DELETE" do
      opts = AuthorizationPlug.init({Auth, permits: ["foo"]})
      conn = conn(:delete, "/") |> authenticate(["foo/delete"])
      assert %{status: nil, state: :unset, halted: false} = AuthorizationPlug.call(conn, opts)
    end
  end

  defp authenticate(conn, scopes \\ []) do
    set_config(secret: "foo", serializer: Serializer.Test)
    opts = AuthenticationPlug.init(Auth)
    compact_token = Auth.token(scopes: scopes) |> Auth.sign()

    conn
    |> put_req_header("authorization", "Bearer #{compact_token}")
    |> AuthenticationPlug.call(opts)
  end
end
