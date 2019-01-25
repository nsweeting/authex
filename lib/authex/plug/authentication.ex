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

    The plug looks for the `Authorization: Bearer mytoken` header. It will then
    verify and deserialize the token using our configured serializer.

    We can then access our current user from the conn using the `c:Authex.current_user/1`
    callback.

    By default, if authentication fails, the plug sends the conn to the `Authex.Plug.Unauthorized`
    plug. This plug will put a `401` status into the conn with the body `"Unauthorized"`.
    We can configure our own unauthorized plug by passing it as an option to the `Authex.Plug.Authentication`
    plug or through our auth module config.

        config :my_app, MyApp.Auth, [
          unauthorized: MyApp.Plug.Unauthorized
        ]
    """

    @behaviour Plug

    import Plug.Conn, only: [get_req_header: 2, put_private: 3]

    @type option :: {:with, Authex.t()} | {:unauthorized, module()}
    @type options :: [option()]

    @doc false
    @impl Plug
    def init(opts \\ []) do
      verify_options(opts) && opts
    end

    @doc false
    @impl Plug
    def call(conn, opts) do
      opts = build_options(opts)

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
      auth = Map.get(opts, :with)
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
      auth = Map.get(opts, :with)

      case apply(auth, :from_token, [token]) do
        {:ok, user} -> {:ok, put_private(conn, :authex_current_user, user)}
        {:error, _} -> :error
      end
    end

    defp unauthorized(conn, opts) do
      handler = Map.get(opts, :unauthorized)
      opts = apply(handler, :init, [opts])
      apply(handler, :call, [conn, opts])
    end

    defp build_options(opts) do
      auth = Keyword.get(opts, :with)

      Enum.into(opts, %{
        unauthorized: auth.config(:unauthorized, Authex.Plug.Unauthorized)
      })
    end

    defp verify_options(opts) do
      Keyword.has_key?(opts, :with) ||
        raise Authex.Error, "Auth module missing. Please pass an auth module using the :with key."
    end
  end
end
