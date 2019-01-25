defmodule Authex.AuthorizationPlug do
  @moduledoc """
  A plug to handle authorization.

  This plug must be passed an auth module in which to authorize with. Otherwise,
  it will raise an `Authex.Error`. The plug must also only be used after the
  `Authex.AuthenticationPlug` has been used.

  With it, we can easily authorize a Phoenix controller:

      defmodule MyAppWeb.MyController do
        use MyAppWeb, :controller

        plug Authex.AuthenticationPlug, auth: MyApp.Auth
        plug Authex.AuthorizationPlug, auth: MyApp.Auth, permits: ["user", "admin"]

        def show(conn, _params) do
          with {:ok, %{id: id}} <- MyApp.Auth.current_user(conn),
              {:ok, user} <- MyApp.Users.get(id)
          do
            render(conn, "show.json", user: user)
          end
        end
      end

  The plug checks the scopes of the token and compares them to the "permits" passed
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

  By default, if authorization fails, the plug sends the conn to the `Authex.ForbiddenPlug`
  plug. This plug will put a `403` status into the conn with the body `"Forbidden"`.
  We can configure our own forbidden plug by passing it as an option to the
  `Authex.AuthorizationPlug` plug or through our config.

      config :my_app, MyApp.Auth, [
        forbidden: MyApp.ForbiddenPlug
      ]
  """

  @behaviour Plug

  import Plug.Conn, only: [put_private: 3]

  @type option :: {:auth, Authex.t()} | {:forbidden, module()}
  @type options :: [option()]

  @doc false
  @impl Plug
  def init(opts \\ []) do
    verify_options(opts) && opts
  end

  @doc false
  @impl Plug
  def call(conn, opts) do
    opts = build_options(opts)

    with {:ok, permits} <- fetch_permits(opts),
         {:ok, action} <- fetch_action(conn),
         {:ok, scopes} <- fetch_current_scopes(conn, opts),
         {:ok, current_scope} <- verify_scope(permits, action, scopes),
         {:ok, conn} <- assign_current_scope(conn, current_scope) do
      conn
    else
      _ -> forbidden(conn, opts)
    end
  end

  defp fetch_permits(opts) do
    case Map.get(opts, :permits) do
      permits when is_list(permits) -> {:ok, permits}
      false -> :error
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

  defp fetch_current_scopes(conn, opts) do
    auth = Map.get(opts, :auth)
    apply(auth, :current_scopes, [conn])
  end

  defp verify_scope(permits, action, scopes) do
    current_scopes =
      Enum.map(permits, fn permit ->
        permit <> "/" <> action
      end)

    case Authex.Token.has_scope?(current_scopes, scopes) do
      false -> :error
      result -> {:ok, result}
    end
  end

  defp assign_current_scope(conn, current_scope) do
    {:ok, put_private(conn, :authex_current_scope, current_scope)}
  end

  defp forbidden(conn, opts) do
    handler = Map.get(opts, :forbidden)
    apply(handler, :call, [conn, []])
  end

  defp build_options(opts) do
    auth = Keyword.get(opts, :auth)

    Enum.into(opts, %{
      forbidden: auth.config(:forbidden, Authex.ForbiddenPlug),
      permits: []
    })
  end

  defp verify_options(opts) do
    Keyword.has_key?(opts, :auth) || raise Authex.Error, "auth module missing"
  end
end
