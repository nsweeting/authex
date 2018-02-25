defmodule Authex.ForbiddenPlug do
  import Plug.Conn

  @spec init(list) :: list
  def init(opts \\ []) do
    opts
  end

  def call(conn, _options) do
    conn
    |> send_resp(403, "Forbidden")
    |> halt()
  end
end
