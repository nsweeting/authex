defmodule Authex.Plug.Authorization do
  import Plug.Conn

  alias Authex.Config
  alias Authex.Token

  @default_opts [
    forbidden: Config.forbidden(),
    permits: []
  ]

  @spec init(list) :: list
  def init(options \\ []) do
    Keyword.merge(@default_opts, options)
  end

  @spec call(Plug.Conn.t, list) :: Plug.Conn.t
  def call(conn, options) do
    with {:ok, permits} <- fetch_permits(options),
         {:ok, action} <- fetch_action(conn),
         {:ok, scopes} <- fetch_current_scopes(conn),
         {:ok, current_scope} <- verify_scope(permits, action, scopes),
         {:ok, conn} <- assign_current_scope(conn, current_scope)
    do
      conn
    else
      _ -> forbidden(conn, options)
    end
  end

  defp fetch_permits(options) do
    case Keyword.get(options, :permits) do
      permits when is_list(permits) -> {:ok, permits}
      false -> :error
    end
  end

  defp fetch_action(%{method: method}) do
    case method do
      "GET"    -> {:ok, "read"}
      "HEAD"   -> {:ok, "read"}
      "PUT"    -> {:ok, "write"}
      "PATCH"  -> {:ok, "write"}
      "POST"   -> {:ok, "write"}
      "DELETE" -> {:ok, "delete"}
      _        -> :error
    end
  end

  defp fetch_current_scopes(conn) do
    Authex.current_scopes(conn)
  end

  defp verify_scope(permits, action, scopes) do
    current_scopes = Enum.map(permits, fn permit ->
      permit <> "/" <> action
    end)

    case Token.has_scope?(current_scopes, scopes) do
      false  -> :error
      result -> {:ok, result}
    end
  end

  defp assign_current_scope(conn, current_scope) do
    {:ok, put_private(conn, :authex_current_scope, current_scope)}
  end

  defp forbidden(conn, options) do
    handler = Keyword.get(options, :forbidden)
    apply(handler, :call, [conn, []])
  end
end
