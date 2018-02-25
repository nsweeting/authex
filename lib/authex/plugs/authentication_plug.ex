defmodule Authex.AuthenticationPlug do
  import Plug.Conn

  def init(opts \\ []) do
    build_options(opts)
  end

  @spec call(Plug.Conn.t(), map) :: Plug.Conn.t()
  def call(conn, opts) do
    with {:ok, compact} <- fetch_header_token(conn),
         {:ok, token} <- verify_token(compact, opts),
         {:ok, conn} <- put_token(conn, token),
         {:ok, conn} <- put_current_user(conn, token, opts) do
      conn
    else
      _ -> unauthorized(conn, opts)
    end
  end

  defp fetch_header_token(conn) do
    case get_req_header(conn, "authorization") do
      [header] -> {:ok, parse_header(header)}
      _ -> :error
    end
  end

  defp verify_token(compact, opts) do
    auth = Map.get(opts, :auth)
    apply(auth, :verify, [compact])
  end

  defp parse_header(header) do
    header
    |> String.split()
    |> List.last()
  end

  defp put_token(conn, token) do
    {:ok, put_private(conn, :authex_token, token)}
  end

  defp put_current_user(conn, token, opts) do
    auth = Map.get(opts, :auth)

    case apply(auth, :from_token, [token]) do
      :error -> :error
      user -> {:ok, put_private(conn, :authex_current_user, user)}
    end
  end

  defp unauthorized(conn, opts) do
    handler = Map.get(opts, :unauthorized)
    opts = apply(handler, :init, [opts])
    apply(handler, :call, [conn, opts])
  end

  defp build_options(opts) do
    auth = Keyword.get(opts, :auth) || raise Authex.Error, "auth module missing"
    Enum.into(opts, %{
      unauthorized: auth.config(:unauthorized, Authex.UnauthorizedPlug)
    })
  end
end
