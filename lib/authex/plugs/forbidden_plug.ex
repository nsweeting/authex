defmodule Authex.ForbiddenPlug do
  @moduledoc """
  A plug to mark the status as forbidden.

  This plug is the default used when authorization fails with `Authex.AuthorizationPlug`.
  It will put a `403` status into the conn with the body `"Forbidden"`.
  """
  @behaviour Plug

  import Plug.Conn

  @impl Plug
  def init(opts \\ []) do
    opts
  end

  @impl Plug
  def call(conn, _opts) do
    conn
    |> send_resp(403, "Forbidden")
    |> halt()
  end
end
