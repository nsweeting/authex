defmodule Authex do
  @moduledoc """
  Defines an auth module.

  This module provides a simple set of tools for the authorization and authentication
  required by a typical API through use of JSON web tokens. To begin, we will want
  to generate a secret from which our tokens will be signed with. There is a convenient
  mix task available for this:

      mix authex.gen.secret

  We should keep this secret as an environment variable.

  Next, we will want to create our auth module

      defmodule MyApp.Auth do
        use Authex

        def start_link(opts \\\\ []) do
          Authex.start_link(__MODULE__, opts, name: __MODULE__)
        end

        # Callbacks

        @impl Authex
        def init(opts) do
          # Add any configuration listed in Authex.start_link/3

          secret = System.get_env("AUTH_SECRET") || "foobar"
          opts = Keyword.put(opts, :secret, secret)

          {:ok, opts}
        end

        @impl Authex
        def handle_for_token(%MyApp.User{} = resource, opts) do
          {:ok, [sub: resource.id, scopes: resource.scopes], opts}
        end

        def handle_for_token(_resource, _opts) do
          {:error, :bad_resource}
        end

        @impl Authex
        def handle_from_token(token, _opts) do
          # You may want to perform a database lookup for your user instead
          {:ok, %MyApp.User{id: token.sub, scopes: token.scopes}}
        end
      end

  We must then add the auth module to our supervision tree.

      children = [
        MyApp.Auth
      ]

  ## Tokens

  At the heart of Authex is the `Authex.Token` struct. This struct is simply
  a wrapper around the typical JWT claims. The only additional item is the
  `:scopes` and `:meta` key. There are 3 base actions required for these tokens -
  creating, signing, and verification.

  #### Creating

  We can easily create token structs using the `token/3` function.

      Authex.token(MyApp.Auth, sub: 1, scopes: ["admin/read"])


  The above would create a token struct for a resource with an id of 1 and with
  "admin/read" authorization.

  #### Signing

  Once we have a token struct, we can sign it using the `sign/3` function to
  create a compact token binary. This is what we will use for authentication and
  authorization for our API.

      token = Authex.token(MyApp.Auth, sub: 1, scopes: ["admin/read"])
      Authex.sign(MyApp.Auth, token)

  #### Verifying

  Once we have a compact token binary, we can verify it and turn it back to an
  token struct using the `verify/3` function.

      token = Authex.token(MyApp.Auth, sub: 1, scopes: ["admin/read"])
      compact_token = Authex.sign(MyApp.Auth, token)
      {:ok, token} = Authex.verify(MyApp.Auth, compact_token)

  ## Callbacks

  Typically, we want to be able to create tokens from another source of data.
  This could be something like a `User` struct. We also will want to take a token
  and turn it back into a `User` struct.

  To do this, we must implement callbacks. For our auth module above, we can
  convert a user to a token.

        token = Authex.for_token(MyApp.Auth, user)
        compact_token = Authex.sign(MyApp.Auth, token)

  As well as turn a token back into a user.

        token = Authex.verify(MyApp.Auth, compact_token)
        user = Authex.from_token(MyApp.Auth, token)

  ## Repositories

  Usually, use of JSON web tokens requires some form of persistence to blacklist
  tokens through their `:jti` claim.

  To do this, we must create a repository. A repository is simply a module that
  adopts the `Authex.Repo` behaviour. For more information on creating
  repositories, please see the `Authex.Repo` documentation.

  Once we have created our blacklist, we define it in our opts when starting our
  auth module or in the `c:init/1` callback.

  During the verification process used by `verify/3`, any blacklist defined in
  our config will be checked against. Please be aware of any performance
  penatly that may be incurred through use of database-backed repo's without use
  of caching.

  ## Plugs

  Authex provides a number of plugs to handle the typical authentication and
  authorization process required by an API using your auth module.

  For more information on handling authentication, please see the `Authex.Plug.Authentication`
  documentation.

  For more information on handling authorization, please see the `Authex.Plug.Authorization`
  documentation.
  """

  alias Authex.{Repo, Server, Signer, Token, Verifier}

  @type alg :: :hs256 | :hs384 | :hs512
  @type signer_option :: {:alg, alg()} | {:secret, binary()}
  @type signer_options :: [signer_option()]
  @type verifier_option ::
          {:alg, alg()}
          | {:time, integer()}
          | {:secret, binary()}
          | {:blacklist, Authex.Blacklist.t()}
  @type verifier_options :: [verifier_option()]
  @type option ::
          {:secret, binary()}
          | {:blacklist, module() | false}
          | {:default_alg, alg()}
          | {:default_iss, binary()}
          | {:default_aud, binary()}
          | {:default_sub, binary() | integer()}
          | {:default_jti, mfa() | binary() | false}
          | {:unauthorized, module()}
          | {:forbidden, module()}
  @type options :: [option()]
  @type t :: module()

  @doc """
  A callback executed when the auth process starts.

  This should be used to dynamically set any config during runtime - such as the
  secret key used to sign tokens with.

  Returns `{:ok, opts}` or `:ignore`.

  ## Example

      def init(opts) do
        secret = System.get_env("AUTH_SECRET")
        opts = Keyword.put(opts, :secret, secret)

        {:ok, opts}
      end
  """
  @callback init(options()) :: {:ok, options()} | :ignore

  @callback handle_for_token(resource :: any(), Keyword.t()) ::
              {:ok, Authex.Token.claims(), signer_options()} | {:error, any()}

  @callback handle_from_token(Authex.Token.t(), Keyword.t()) ::
              {:ok, resource :: any()} | {:error, any()}

  @doc """
  Starts the auth process.

  Returns `{:ok, pid}` on success.

  Returns `{:error, {:already_started, pid}}` if the auth process is already
  started or `{:error, term}` in case anything else goes wrong.

  ## Options

    * `:secret` -  The secret used to sign tokens with.
    * `:blacklist` - A blacklist repo, or false if disabled - defaults to `false`.
    * `:default_alg` - The default algorithm used to sign tokens - defaults to `:hs256`.
    * `:default_iss` - The default iss claim used in tokens.
    * `:default_aud` - The default aud claim used in tokens.
    * `:default_ttl` - The default time to live for tokens in seconds.
    * `:default_jti` - The default mfa used to generate the jti claim. Can be `false`
      if you do not want to generate one - defaults to `{Authex.UUID, :generate, []}`.
  """
  @spec start_link(Authex.t(), options(), GenServer.options()) :: GenServer.on_start()
  def start_link(module, opts \\ [], server_opts \\ []) do
    Server.start_link(module, opts, server_opts)
  end

  @doc """
  Creates a new token.

  A token is a struct that wraps the typical JWT claims but also adds a couple
  new fields. Please see the `Authex.Token` documentation for more details.

  Returns an `Authex.Token` struct.

  ## Options
    * `:time` - The base time (timestamp format) in which to use.
    * `:ttl` - The time-to-live for the token in seconds or `:infinity` if no expiration
      is required. The lifetime is based on the time provided via the options,
      or the current time if not provided.

  ## Example

      Authex.token(MyAuth, sub: 1, scopes: ["admin/read"])
  """
  @spec token(Authex.t(), Authex.Token.claims(), Authex.Token.options()) :: Authex.Token.t()
  def token(module, claims \\ [], opts \\ []) do
    Token.new(module, claims, opts)
  end

  @doc """
  Signs a token, creating a compact token.

  The compact token is a binary that can be used for authentication and authorization
  purposes. Typically, this would be placed in an HTTP header, such as:

  ```bash
  Authorization: Bearer mytoken
  ```

  Returns `compact_token` or raises an `Authex.Error`.

  ## Options
    * `:secret` - The secret key to sign the token with.
    * `:alg` - The algorithm to sign the token with - defaults to `:hs256`

  Any option provided would override the default set in the config.
  """
  @spec sign(Authex.t(), Authex.Token.t(), signer_options()) :: binary()
  def sign(module, %Authex.Token{} = token, opts \\ []) do
    module
    |> Signer.new(opts)
    |> Signer.compact(token)
  end

  @doc """
  Generates a compact token from a set of claims.

  This is simply a shortened version of calling `token/3` and `sign/3`.

  ## Options

  All options are the same available in `token/3` and `sign/3`.
  """
  @spec compact_token(Authex.t(), Authex.Token.claims(), signer_options()) :: binary()
  def compact_token(module, claims \\ [], opts \\ []) do
    token = token(module, claims, opts)
    sign(module, token, opts)
  end

  @doc """
  Verifies a compact token.

  Verification is a multi-step process that ensures:

  1. The token has not been tampered with.
  2. The current time is not before the `nbf` value.
  3. The current time is not after the `exp` value.
  4. The token `jti` is not included in the blacklist (if provided).

  If all checks pass, the token is deemed verified.

  Returns `{:ok, token}` or `{:error, reason}`.

  ## Options
    * `:time` - The base time (timestamp format) in which to use.
    * `:secret` - The secret key to verify the token with.
    * `:alg` - The algorithm to verify the token with
    * `:blacklist` - The blacklist module to verify with.

  Any option provided would override the default set in the config.

  ## Example

      {:ok, token} = Authex.verify(MyAuth, compact_token)
  """
  @spec verify(Authex.t(), binary(), verifier_options()) ::
          {:ok, Authex.Token.t()}
          | {:error,
             :bad_token
             | :not_ready
             | :expired
             | :blacklisted
             | :blacklist_error
             | :jti_unverified}
  def verify(module, compact_token, opts \\ []) do
    Verifier.run(module, compact_token, opts)
  end

  @doc """
  Refreshes an `Authex.Token` into a new `Authex.Token`.

  When using this function, the assumption has already been made that you have
  verified it with `verify/3`. This will extract the following claims from the
  original token:

    * `:sub`
    * `:iss`
    * `:aud`
    * `:scopes`
    * `:meta`

  It will then take these claims and generate a new token with them.

  ## Options

  Please see the options available at `token/3`.

  ## Example

      token = Authex.refresh(token)
  """
  @spec refresh(Authex.t(), Authex.Token.t(), Authex.Token.options()) :: Authex.Token.t()
  def refresh(module, token, opts \\ []) do
    claims =
      token
      |> Map.from_struct()
      |> Enum.into([])
      |> Keyword.take([:sub, :iss, :aud, :scopes, :meta])

    token(module, claims, opts)
  end

  @doc """
  Converts an `Authex.Token` into a resource.

  This invokes the `c:handle_from_token/2` defined in the auth module. Please see
  the callback docs for further details.

  Returns `{:ok, resource}` or `{:error, reason}`.

  ## Options

  You can also include any additional options your callback might need.

  ## Example

      {:ok, user} = Authex.from_token(token)
  """
  @spec from_token(Authex.t(), Authex.Token.t(), verifier_options() | Keyword.t()) ::
          {:ok, any()} | {:error, any()}
  def from_token(module, %Token{} = token, opts \\ []) do
    module.handle_from_token(token, opts)
  end

  @doc """
  Converts a resource into an `Authex.Token`.

  This invokes the `c:handle_for_token/2` callback defined in the auth module. Please
  see the callback docs for further details.

  Returns `{:ok, token}` or `{:error, reason}`

  ## Options

  Please see the options available in `token/3`. You can also include any
  additional options your callback might need.

  ## Example

      {:ok, token} = Authex.for_token(MyAuth, user)
  """
  @spec for_token(Authex.t(), resource :: any(), signer_options() | Keyword.t()) ::
          {:ok, Authex.Token.t()} | {:error, any()}
  def for_token(module, resource, opts \\ []) do
    with {:ok, claims, opts} <- module.handle_for_token(resource, opts) do
      {:ok, token(module, claims, opts)}
    end
  end

  @doc """
  Gets the current resource from a `Plug.Conn`.

  The resource will only be accessible if the `conn` has been run through the
  `Authex.Plug.Authentication` plug.

  Returns `{:ok, resource}` or `:error`.
  """
  @spec current_resource(conn :: Plug.Conn.t()) :: {:ok, any()} | :error
  def current_resource(_conn = %{private: private}) do
    Map.fetch(private, :authex_resource)
  end

  def current_resource(_) do
    :error
  end

  @doc """
  Gets the current scopes from a `Plug.Conn`.

  The scopes will only be accessible if the `conn` has been run through the
  `Authex.Plug.Authentication` plug.

  Returns `{:ok, scopes}` or `:error`.
  """
  @spec current_scopes(conn :: Plug.Conn.t()) :: {:ok, [binary()]} | :error
  def current_scopes(conn) do
    with {:ok, token} <- current_token(conn) do
      Map.fetch(token, :scopes)
    end
  end

  @doc """
  Gets the current scope from a `Plug.Conn`.

  The scope will only be accessible if the `conn` has been run through the
  `Authex.Plug.Authorization` plug.

  Returns `{:ok, scope}` or `:error`.
  """
  @spec current_scope(conn :: Plug.Conn.t()) :: {:ok, [binary()]} | :error
  def current_scope(_conn = %{private: private}) do
    Map.fetch(private, :authex_scope)
  end

  def current_scope(_) do
    :error
  end

  @doc """
  Gets the current token from a `Plug.Conn`.

  The token will only be accessible if the `conn` has been run through the
  `Authex.Plug.Authentication` plug.

  Returns `{:ok, token}` or `:error`.
  """
  @spec current_token(conn :: Plug.Conn.t()) :: {:ok, Authex.Token.t()} | :error
  def current_token(_conn = %{private: private}) do
    Map.fetch(private, :authex_token)
  end

  def current_token(_) do
    :error
  end

  @doc """
  Checks whether a token jti is blacklisted.

  This uses the blaclist repo defined in the auth config. The key is the `:jti`
  claim in the token.

  Returns a boolean.

  ## Example

      Authex.blacklisted?(MyAuth, token)
  """
  @spec blacklisted?(Authex.t(), Authex.Token.t()) :: boolean() | :error
  def blacklisted?(module, %Authex.Token{jti: jti}) do
    blacklist = config(module, :blacklist, false)
    Repo.exists?(blacklist, jti)
  end

  @doc """
  Blacklists a token jti.

  This uses the blaclist repo defined in the auth config. The key is the `:jti`
  claim in the token.

  Returns `:ok` on success, or `:error` on failure.

  ## Example

      Authex.blacklist(MyAuth, token)
  """
  @spec blacklist(Authex.t(), Authex.Token.t()) :: :ok | :error
  def blacklist(module, %Authex.Token{jti: jti}) do
    blacklist = config(module, :blacklist, false)
    Repo.insert(blacklist, jti)
  end

  @doc """
  Unblacklists a token jti.

  This uses the blaclist repo defined in the auth config. The key is the `:jti`
  claim in the token.

  Returns `:ok` on success, or `:error` on failure.

  ## Example

      MyApp.Auth.unblacklist(token)
  """
  @spec unblacklist(Authex.t(), Authex.Token.t()) :: :ok | :error
  def unblacklist(module, %Authex.Token{jti: jti}) do
    blacklist = config(module, :blacklist, false)
    Repo.delete(blacklist, jti)
  end

  @doc """
  Fetches a config value.

  ## Example

      Authex.config(MyAuth, :secret)
  """
  @spec config(Authex.t(), atom(), any()) :: any()
  def config(module, key, default \\ nil) do
    Server.config(module, key, default)
  end

  defmacro __using__(_opts) do
    quote do
      @behaviour Authex

      if Module.get_attribute(__MODULE__, :doc) == nil do
        @doc """
        Returns a specification to start this Authex process under a supervisor.

        See `Supervisor`.
        """
      end

      def child_spec(args) do
        %{
          id: __MODULE__,
          start: {__MODULE__, :start_link, [args]}
        }
      end

      defoverridable(child_spec: 1)
    end
  end
end
