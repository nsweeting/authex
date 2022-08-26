if Code.ensure_loaded?(Plug) do
  defmodule Authex.Plug.Authentication do
    @moduledoc """
    A plug to handle authentication.

    This plug must be passed an auth module in which to authenticate with. Otherwise,
    it will raise an `Authex.Error`.

    With it, we can easily authenticate a Phoenix controller:

        defmodule MyAppWeb.MyController do
          use MyAppWeb, :controller

          plug Authex.Plug.Authentication, with: MyApp.Auth

          def show(conn, _params) do
            with {:ok, %{id: id}} <- MyApp.Auth.current_user(conn),
                {:ok, user} <- MyApp.Users.get(id)
            do
              render(conn, "show.json", user: user)
            end
          end
        end

    The plug looks for the `Authorization: Bearer mytoken` header by default. It
    will then verify and covert out token into a resource using the provided auth
    module. You can optionally set a `:param` value to enable tokens from query
    parameters.

    We can then access our current resource from the conn using `Authex.current_resource/1`.

    By default, if authentication fails, the plug sends the conn to the `Authex.Plug.Unauthorized`
    plug. This plug will put a `401` status into the conn with the body `"Unauthorized"`.
    We can configure our own unauthorized plug by passing it as an option to this plug.

    ## Options

      * `:with` - The auth module that will be used for verification and token conversion.
      * `:unauthorized` - The plug to call when the token is invalid - defaults to `Authex.Plug.Unauthorized`.
      * `:header` - The header to extract the token from - defaults to `"authorization"`.
      * `:param` - A query parameter to extract tokens from - defaults to `nil` (no use of params).
    """

    @behaviour Plug

    import Plug.Conn, only: [get_req_header: 2, put_private: 3]

    @type option :: {:with, Authex.t()} | {:unauthorized, module()} | {:header, binary()}
    @type options :: [option()]

    @doc false
    @impl Plug
    def init(opts \\ []) do
      verify_options(opts)
      build_options(opts)
    end

    @doc false
    @impl Plug
    def call(conn, opts) do
      with {:ok, compact} <- fetch_token(conn, opts),
           {:ok, token} <- verify_token(compact, opts),
           {:ok, conn} <- put_token(conn, token),
           {:ok, conn} <- put_current_resource(conn, token, opts) do
        conn
      else
        _ -> unauthorized(conn, opts)
      end
    end

    defp fetch_token(conn, opts) do
      with :error <- fetch_header_token(conn, opts) do
        fetch_param_token(conn, opts)
      end
    end

    defp fetch_header_token(conn, opts) do
      case get_req_header(conn, opts.header) do
        [header] -> {:ok, parse_header(header)}
        _ -> :error
      end
    end

    defp fetch_param_token(conn, opts) do
      case opts.param && Map.get(conn.params, opts.param) do
        val when is_binary(val) -> {:ok, val}
        _ -> :error
      end
    end

    defp verify_token(compact, opts) do
      Authex.verify(opts.with, compact)
    end

    defp parse_header(header) do
      header
      |> String.split()
      |> List.last()
    end

    defp put_token(conn, token) do
      {:ok, put_private(conn, :authex_token, token)}
    end

    defp put_current_resource(conn, token, opts) do
      case Authex.from_token(opts.with, token) do
        {:ok, resource} -> {:ok, put_private(conn, :authex_resource, resource)}
        {:error, _} -> :error
      end
    end

    defp unauthorized(conn, opts) do
      opts = apply(opts.unauthorized, :init, [opts])
      apply(opts.unauthorized, :call, [conn, opts])
    end

    defp verify_options(opts) do
      Keyword.has_key?(opts, :with) ||
        raise Authex.Error, "Auth module missing. Please pass an auth module using the :with key."
    end

    defp build_options(opts) do
      %{
        with: Keyword.fetch!(opts, :with),
        header: Keyword.get(opts, :header, "authorization"),
        param: Keyword.get(opts, :param),
        unauthorized: Keyword.get(opts, :unauthorized, Authex.Plug.Unauthorized)
      }
    end
  end
end
