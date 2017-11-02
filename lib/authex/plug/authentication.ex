defmodule Authex.Plug.Authentication do
  import Plug.Conn

  @unauthorized Authex.Plug.Unauthorized
  @serializer Authex.Serializer.Basic

  @spec init(list) :: list
  def init(options \\ []) do
    options
    |> Keyword.put_new(:unauthorized, @unauthorized)
    |> Keyword.put_new(:serializer, @serializer)
  end

  @spec call(Plug.Conn.t, list) :: Plug.Conn.t
  def call(conn, options) do
    with {:ok, compact} <- fetch_token(conn),
         {:ok, token} <- Authex.verify(compact),
         {:ok, conn} <- assign_user(conn, token, options),
         {:ok, conn} <- assign_scopes(conn, token)
    do
      conn
    else
      _ -> unauthorized(conn, options)
    end
  end

  defp fetch_token(conn) do
    case get_req_header(conn, "authorization") do
      [header] -> {:ok, extract_token(header)}
      _        -> :error
    end
  end

  defp assign_user(conn, token, options) do
    serializer = Keyword.get(options, :serializer)
    case apply(serializer, :from_token, [token]) do
      :error -> :error
      user -> {:ok, assign(conn, :current_user, user)}
    end
  end

  defp assign_scopes(conn, token) do
    assign(conn, :token_scopes, token.scopes)
  end

  defp extract_token(header) do
    header
    |> String.split()
    |> List.last()
  end

  defp unauthorized(conn, options) do
    handler = Keyword.get(options, :unauthorized)
    options = apply(handler, :init, [options])
    apply(handler, :call, [conn, options])
  end
end
