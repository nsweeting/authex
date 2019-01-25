if Code.ensure_loaded?(Plug) do
  defmodule Authex.Plug.Forbidden do
    @moduledoc """
    A plug to mark the status as forbidden.

    This plug is the default used when authorization fails with `Authex.Plug.Authorization`.
    It will put a `403` status into the conn with the body `"Forbidden"`.
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
    def call(conn, _opts) do
      conn
      |> send_resp(403, "Forbidden")
      |> halt()
    end
  end
end
