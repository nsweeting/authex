defmodule Authex.Plug.Unauthorized do
  import Plug.Conn

  @spec init(list) :: list
  def init(options \\ []) do
    options
  end

  def call(conn, _options) do
    conn
    |> send_resp(401, "Not Authorized")
    |> halt()
  end
end
