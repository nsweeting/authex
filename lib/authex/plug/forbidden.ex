defmodule Authex.Plug.Forbidden do
  import Plug.Conn

  @spec init(list) :: list
  def init(options \\ []) do
    options
  end

  def call(conn, _options) do
    conn
    |> send_resp(403, "Forbidden")
    |> halt()
  end
end
