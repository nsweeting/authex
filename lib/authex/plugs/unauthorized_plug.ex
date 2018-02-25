defmodule Authex.UnauthorizedPlug do
  import Plug.Conn

  @spec init(list) :: list
  def init(opts \\ []) do
    opts
  end

  def call(conn, _options) do
    conn
    |> send_resp(401, "Not Authorized")
    |> halt()
  end
end
