if Code.ensure_loaded?(Plug) do
  defmodule Authex.UnauthorizedPlug do
    @moduledoc """
    A plug to mark the status as unauthorized.

    This plug is the default used when authentication fails with `Authex.AuthenticationPlug`.
    It will put a `401` status into the conn with the body `"Unauthorized"`.
    """

    @behaviour Plug

    import Plug.Conn, only: [send_resp: 3, halt: 1]

    @doc false
    @impl Plug
    def init(opts \\ []) do
      opts
    end

    @doc false
    @impl Plug
    def call(conn, _options) do
      conn
      |> send_resp(401, "Not Authorized")
      |> halt()
    end
  end
end
