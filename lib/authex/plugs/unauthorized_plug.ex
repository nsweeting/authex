defmodule Authex.UnauthorizedPlug do
  @moduledoc """
  A plug to mark the status as unauthorized.

  This plug is the default used when authentication fails with `Authex.AuthenticationPlug`.
  It will put a `401` status into the conn with the body `"Unauthorized"`.
  """

  @behaviour Plug

  import Plug.Conn

  @impl Plug
  def init(opts \\ []) do
    opts
  end

  @impl Plug
  def call(conn, _options) do
    conn
    |> send_resp(401, "Not Authorized")
    |> halt()
  end
end
