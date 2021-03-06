if Code.ensure_loaded?(Plug) do
  defmodule Authex.Plug.Authorization do
    @moduledoc """
    A plug to handle authorization.

    The plug must also only be used after the `Authex.Plug.Authentication` has been used.

    With it, we can easily authorize a Phoenix controller:

        defmodule MyAppWeb.MyController do
          use MyAppWeb, :controller

          plug Authex.Plug.Authentication, with: MyApp.Auth
          plug Authex.Plug.Authorization, permits: ["user", "admin"]

          def show(conn, _params) do
            with {:ok, %{id: id}} <- Authex.current_resource(conn),
                {:ok, user} <- MyApp.Users.get(id)
            do
              render(conn, "show.json", user: user)
            end
          end
        end

    The plug checks the scopes of the token and compares them to the `:permits` passed
    to the plug. Authorization works by combining the "permits" with the "type" of
    request that is being made.

    For example, with our controller above, we are permitting "user" and "admin" access.
    The show action would be a `GET` request, and would therefore be a "read" type.

    Requests are bucketed under the following types:

      * GET - read
      * HEAD - read
      * PUT - write
      * PATCH - write
      * POST - write
      * DELETE - delete

    So, in order to access the show action, our token would require one of the
    following scopes: `["user/read", "admin/read"]`. Or, the token would require
    `["user/write", "admin/write"]` to access the update action.

    By default, if authorization fails, the plug sends the conn to the `Authex.Plug.Forbidden`
    plug. This plug will put a `403` status into the conn with the body `"Forbidden"`.
    We can configure our own forbidden plug by passing it as an option to this plug.

    ## Options

      * `:forbidden` - The plug to call when the scopes are invalid - defaults to `Authex.Plug.Forbidden`.
      * `:permits` - A list of permits that the token scopes must have at least one of.
    """

    @behaviour Plug

    import Plug.Conn, only: [put_private: 3]

    @type option :: {:forbidden, module()} | {:permits, [binary()]}
    @type options :: [option()]

    @doc false
    @impl Plug
    def init(opts \\ []) do
      build_options(opts)
    end

    @doc false
    @impl Plug
    def call(conn, opts) do
      with {:ok, action} <- fetch_action(conn),
           {:ok, scopes} <- fetch_current_scopes(conn),
           {:ok, scope} <- verify_scope(opts, action, scopes),
           {:ok, conn} <- assign_scope(conn, scope) do
        conn
      else
        _ -> forbidden(conn, opts)
      end
    end

    defp fetch_action(%{method: method}) do
      case method do
        "GET" -> {:ok, "read"}
        "HEAD" -> {:ok, "read"}
        "PUT" -> {:ok, "write"}
        "PATCH" -> {:ok, "write"}
        "POST" -> {:ok, "write"}
        "DELETE" -> {:ok, "delete"}
        _ -> :error
      end
    end

    defp fetch_current_scopes(conn) do
      Authex.current_scopes(conn)
    end

    defp verify_scope(opts, action, scopes) do
      current_scopes =
        Enum.map(opts.permits, fn permit ->
          permit <> "/" <> action
        end)

      case Authex.Token.has_scope?(current_scopes, scopes) do
        false -> :error
        result -> {:ok, result}
      end
    end

    defp assign_scope(conn, scope) do
      {:ok, put_private(conn, :authex_scope, scope)}
    end

    defp forbidden(conn, opts) do
      opts = apply(opts.forbidden, :init, [opts])
      apply(opts.forbidden, :call, [conn, opts])
    end

    defp build_options(opts) do
      %{
        forbidden: Keyword.get(opts, :forbidden, Authex.Plug.Forbidden),
        permits: Keyword.get(opts, :permits, [])
      }
    end
  end
end
