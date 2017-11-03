defmodule Authex.Plug.Authentication do
  import Plug.Conn

  alias Authex.Config

  @default_opts [
    unauthorized: Config.unauthorized(),
    serializer:   Config.serializer(),
  ]

  @spec init(list) :: list
  def init(options \\ []) do
    Keyword.merge(@default_opts, options)
  end

  @spec call(Plug.Conn.t, list) :: Plug.Conn.t
  def call(conn, options) do
    with {:ok, compact} <- fetch_header_token(conn),
         {:ok, token} <- Authex.verify(compact),
         {:ok, conn} <- put_token(conn, token),
         {:ok, conn} <- put_current_user(conn, token, options)
    do
      conn
    else
      _ -> unauthorized(conn, options)
    end
  end

  defp fetch_header_token(conn) do
    case get_req_header(conn, "authorization") do
      [header] -> {:ok, parse_header(header)}
      _        -> :error
    end
  end

  defp parse_header(header) do
    header
    |> String.split()
    |> List.last()
  end

  defp put_token(conn, token) do
    put_private(conn, :authex_token, token)
  end

  defp put_current_user(conn, token, options) do
    serializer = Keyword.get(options, :serializer)
    case apply(serializer, :from_token, [token]) do
      :error -> :error
      user -> {:ok, put_private(conn, :authex_current_user, user)}
    end
  end

  defp unauthorized(conn, options) do
    handler = Keyword.get(options, :unauthorized)
    options = apply(handler, :init, [options])
    apply(handler, :call, [conn, options])
  end
end
