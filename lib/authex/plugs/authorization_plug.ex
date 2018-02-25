defmodule Authex.AuthorizationPlug do
  import Plug.Conn

  alias Authex.Token

  def init(opts \\ []) do
    build_options(opts)
  end

  @spec call(Plug.Conn.t(), map) :: Plug.Conn.t()
  def call(conn, opts) do
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

    case Token.has_scope?(current_scopes, scopes) do
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
    auth = Keyword.get(opts, :auth) || raise Authex.Error, "auth module missing"
    Enum.into(opts, %{
      forbidden: auth.config(:forbidden, Authex.ForbiddenPlug),
      permits: []
    })
  end
end
