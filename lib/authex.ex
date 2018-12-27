defmodule Authex do
  @moduledoc """
  Defines an auth module.

  This module provides a simple set of tools for the authorization and authentication
  required by a typical API through use of JSON web tokens. To get started, we
  need to define our auth module:

      defmodule MyApp.Auth do
        use Authex, otp_app: :my_app
      end

  We must then add the auth module to our supervision tree.

      children = [
        MyApp.Auth
      ]

  ## Configuration

  While our auth module is defined, we will need to further configure it to our
  requirements. At a minimum, we need to add a secret from which our tokens will
  be signed with. There is a convenient mix task available for this:

      mix authex.gen.secret

  We should now add this secret to our config. In production this should be set
  via an env var. We should use the `c:init/1` callback to configure this:

      defmodule MyApp.Auth do
        use Authex, otp_app: :my_app

        def init(config) do
          secret = System.get_env("AUTH_SECRET")
          config = Keyword.put(config, :secret, secret)

          {:ok, config}
        end
      end

  Any other config can either be set with the `c:start_link/1` or `c:init/1` callbacks,
  or via application config. Below are some of the values available:

      config :my_app, MyApp.Auth, [
        # REQUIRED
        # The secret used to sign tokens with.
        secret: "mysecret",

        # OPTIONAL
        # A blacklist repo, or false if disabled.
        blacklist: false,
        # A banlist repo, or false if disabled.
        banlist: false,
        # The default algorithm used to sign tokens.
        default_alg: :hs256,
        # The default iss claim used in tokens.
        default_iss: nil,
        # The default aud claim used in tokens.
        default_aud: nil,
        # The default time to live for tokens in seconds.
        default_ttl: 3600,
        # The default module, function, and arg used to generate the jti claim.
        jti_mfa: {UUID, :uuid4, [:hex]}
        # The plug called when an unauthorized status is determined.
        unauthorized: Authex.UnauthorizedPlug
        # The plug called when an forbidden status is determined.
        forbidden: Authex.ForbiddenPlug
      ]

  ## Tokens

  At the heart of Authex is the `Authex.Token` struct. This struct is simply
  a wrapper around the typical JWT claims. The only additional item is the
  `:scopes` and `:meta` key. There are 3 base actions required for these tokens -
  creation, signing, and verification.

  #### Creating

  We can easily create token structs using the `c:token/2` function.


      MyApp.Auth.token(sub: 1, scopes: ["admin/read"])


  The above would create a token struct for a user with an id of 1 and with
  "admin/read" authorization.

  #### Signing

  Once we have a token struct, we can sign it using the `c:sign/2` function to
  create a compact token binary. This is what we will use for authentication and
  authorization for our API.

      [sub: 1, scopes: ["admin/read"]]
      |> MyApp.Auth.token()
      |> MyApp.Auth.sign()

  #### Verifying

  Once we have a compact token binary, we can verify it and turn it back to an
  token struct using the `c:verify/2` function.

      [sub: 1, scopes: ["admin/read"]]
      |> MyApp.Auth.token()
      |> MyApp.Auth.sign()
      |> MyApp.Auth.verify()

  ## Serializers

  Typically, we want to be able to create tokens from another source of data.
  This could be something like a `User` struct. We also will want to take a token
  and turn it back into a `User` struct.

  To do this, we must create a serializer. A serializer is simply a module that
  adopts the `Authex.Serializer` behaviour. For more information on creating
  serializers, please see the `Authex.Serializer` documention.

  Once we have created our serializer, we define it in our config.

      config :my_app, MyApp.Auth, [
        serializer: MyApp.Auth.UserSerializer,
      ]

  We can now easily create tokens and compact tokens from our custom data using
  the `c:for_token/2` and `c:for_compact_token/3` functions.


      user = %MyApp.User{id: 1, scopes: []}

      {:ok, token} = MyApp.Auth.for_token(user) # returns a token struct
      {:ok, compact_token} = MyApp.Auth.for_compact_token(user) # returns a compact token


  We can also turn tokens and compact tokens back into our custom data using the
  `c:from_token/2` and `c:from_compact_token/2` functions.


      user = %MyApp.User{id: 1, scopes: []}

      {:ok, token} = MyApp.Auth.for_token(user)
      {:ok, user} = MyApp.Auth.from_token(token)

      {:ok, compact_token} = MyApp.Auth.for_compact_token(user)
      {:ok, user} = MyApp.Auth.from_compact_token(compact_token)

  ## Repositories

  Usually, use of JSON web tokens requires some form of persistence to blacklist
  tokens through their `:jti` claim. Authex also adds the ability to ban a
  token through its `:sub` claim.

  To do this, we must create a repository. A repository is simply a module that
  adopts the `Authex.Repo` behaviour. For more information on creating
  repositories, please see the `Authex.Repo` documention.

  Once we have created our blacklist or banlist repo, we define it in our config.

      config :my_app, MyApp.Auth, [
        blacklist: MyApp.Auth.Blacklist,
        banlist: MyApp.Auth.Banlist
      ]

  During the verification process used by `c:verify/2`, any blacklist or banlist
  defined in our config will be checked against. Please be aware of any performance
  penatly that may be incurred through use of database-backed repo's without use
  of caching.

  ## Plugs

  Authex provides a number of plugs to handle the typical authentication and
  authorization process required by an API using your auth module.

  For more information on handling authentication, please see the `Authex.AuthenticationPlug`
  documention.

  For more information on handling authorization, please see the `Authex.AuthorizationPlug`
  documention.
  """

  @type alg :: :hs256 | :hs384 | :hs512

  @type signer_option :: {:alg, alg()} | {:secret, binary()}

  @type signer_options :: [signer_option()]

  @type verifier_option ::
          {:alg, alg()}
          | {:time, integer()}
          | {:secret, binary()}
          | {:banlist, Authex.Banlist.t()}
          | {:blacklist, Authex.Blacklist.t()}

  @type verifier_options :: [verifier_option()]

  @type t :: module()

  @doc """
  Starts the auth process.

  Returns `{:ok, pid}` on success.

  Returns `{:error, {:already_started, pid}}` if the auth process is already
  started or `{:error, term}` in case anything else goes wrong.

  ## Options

  See the configuration in the moduledoc for options.
  """
  @callback start_link(config :: Keyword.t()) :: GenServer.on_start()

  @doc """
  A callback executed when the auth process starts.

  This should be used to dynamically set any config during runtime - such as the
  secret key used to sign tokens with.

  Returns `{:ok, config}`

  ## Example

      def init(config) do
        secret = System.get_env("AUTH_SECRET")
        config = Keyword.put(config, :secret, secret)

        {:ok, config}
      end
  """
  @callback init(config :: Keyword.t()) :: {:ok, Keyword.t()}

  @doc """
  Creates a new token.

  A token is a struct that wraps the typical JWT claims but also adds a couple
  new fields. Please see the `Authex.Token` documentation for more details.

  Returns an `Authex.Token` struct,

  ## Options
    * `:time` - The base time (timestamp format) in which to use.
    * `:ttl` - The time-to-live for the token in seconds. The lifetime is based
    on the time provided via the options, or the current time if not provided.

  ## Example

      MyApp.Auth.token(sub: 1, scopes: ["admin/read"])
  """
  @callback token(claims :: Authex.Token.claims(), options :: Authex.Token.options()) ::
              Authex.Token.t()

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
    * `:alg` - The algorithm to sign the token with.

  Any option provided would override the default set in the config.
  """
  @callback sign(token :: Authex.Token.t(), signer_options()) ::
              Authex.Token.compact() | no_return()

  @doc """
  Verifies a compact token.

  Verification is a multi-step process that ensures:

  1. The token has not been tampered with.
  2. The current time is not before the `nbf` value.
  3. The current time is not after the `exp` value.
  4. The token `jti` is not included in the blacklist (if provided).
  5. The token `sub` is not included in the banlist (if provided).

  If all checks pass, the token is deemed verified.

  ## Options
    * `:time` - The base time (timestamp format) in which to use.
    * `:secret` - The secret key to verify the token with.
    * `:alg` - The algorithm to verify the token with
    * `:banlist` - The banlist module to verify with.
    * `:blacklist` - The blacklist module to verify with.

  Any option provided would override the default set in the config.

  Returns `{:ok, token}` or `{:error, reason}`

  ## Example

      {:ok, token} = MyApp.Auth.verify(compact_token)
  """
  @callback verify(compact_token :: Authex.Token.compact(), options :: verifier_options()) ::
              {:ok, Authex.Token.t()} | {:error, term()}

  @doc """
  Converts an `Authex.Token` struct into a resource.

  This uses the serializer defined in the auth config. It will invoke the
  `c:Authex.Serializer.from_token/2` callback defined in the serializer module.
  Please see the `Authex.Serializer` documentation for more details on implementing
  a serializer.

  Returns `{:ok, resource}` or `{:error, reason}`

  ## Options

  Any additional options your serializer might need.

  ## Example

      {:ok, user} = MyApp.Auth.from_token(token)
  """
  @callback from_token(token :: Authex.Token.t(), options :: Keyword.t()) ::
              {:ok, term()} | {:error, term()}

  @doc """
  Verifies and converts a compact token into a resource.

  Once verified, this invokes `c:from_token/2` with the verified token. Please see
  `c:from_token/2` for additional details.

  Returns `{:ok, resource}` or `{:error, reason}`

  ## Options

  Please see the options available in `c:verify/2`. You can also include any
  additional options your serializer might need.

  ## Example

      {:ok, user} = MyApp.Auth.from_compact_token(compact_token)
  """
  @callback from_compact_token(
              compact_token :: Authex.Token.compact(),
              verifier_options()
            ) :: {:ok, term()} | {:error, atom}

  @doc """
  Converts a resource into an `Authex.Token` struct.

  This uses the serializer defined in the auth config. It will invoke the
  `c:Authex.Serializer.for_token/2` callback defined in the serializer module.
  Please see the `Authex.Serializer` documentation for more details on implementing
  a serializer.

  Returns `{:ok, token}` or `{:error, reason}`

  ## Options

  Please see the options available in `c:token/2`.

  ## Example

      {:ok, token} = MyApp.Auth.for_token(user)
  """
  @callback for_token(term(), options :: Authex.Token.options()) ::
              {:ok, Authex.Token.t()} | {:error, term()}

  @doc """
  Converts a resource into a compact token.

  Returns `{:ok, compact_token}` or `{:error, reason}`

  ## Options

  Please see the options available in `c:token/2`.

  ## Example

      {:ok, compact_token} = MyApp.Auth.for_compact_token(user)
  """
  @callback for_compact_token(term(), token_opts :: Authex.Token.options(), signer_options()) ::
              {:ok, Authex.Token.compact()} | {:error, term()}

  @doc """
  Gets the current user from a `Plug.Conn`.
  """
  @callback current_user(Plug.Conn.t()) :: {:ok, term()} | :error

  @doc """
  Gets the current scopes from a `Plug.Conn`.
  """
  @callback current_scopes(Plug.Conn.t()) :: {:ok, list} | :error

  @doc """
  Checks whether a token subject is banned.

  This uses the banlist repo defined in the auth config. The key is the `:sub`
  key in the token.

  Returns a boolean.

  ## Example

      MyApp.Auth.banned?(token)
  """
  @callback banned?(token :: Authex.Token.t()) :: boolean

  @doc """
  Bans a token subject.

  This uses the banlist repo defined in the auth config. The key is the `:sub`
  key in the token.

  Returns `:ok` on success, or `:error` on failure.

  ## Example

      MyApp.Auth.ban(token)
  """
  @callback ban(token :: Authex.Token.t()) :: :ok | :error

  @doc """
  Unbans a token subject.

  This uses the banlist repo defined in the auth config. The key is the `:sub`
  key in the token.

  Returns `:ok` on success, or `:error` on failure.

  ## Example

      MyApp.Auth.unban(token)
  """
  @callback unban(token :: Authex.Token.t()) :: :ok | :error

  @doc """
  Checks whether a token jti is blacklisted.

  This uses the blaclist repo defined in the auth config. The key is the `:jti`
  key in the token.

  Returns a boolean.

  ## Example

      MyApp.Auth.blacklisted?(token)
  """
  @callback blacklisted?(token :: Authex.Token.t()) :: boolean

  @doc """
  Blacklists a token jti.

  This uses the blaclist repo defined in the auth config. The key is the `:jti`
  key in the token.

  Returns `:ok` on success, or `:error` on failure.

  ## Example

      MyApp.Auth.blacklist(token)
  """
  @callback blacklist(token :: Authex.Token.t()) :: :ok | :error

  @doc """
  Unblacklists a token jti.

  This uses the blaclist repo defined in the auth config. The key is the `:jti`
  key in the token.

  Returns `:ok` on success, or `:error` on failure.

  ## Example

      MyApp.Auth.unblacklist(token)
  """
  @callback unblacklist(token :: Authex.Token.t()) :: :ok | :error

  @doc """
  Saves the config that is currently associated with our auth module.
  """
  @callback save_config() :: :ok | :error

  @doc """
  Sets the config that is used with our auth module.
  """
  @callback save_config(keyword()) :: :ok | :error

  @doc """
  Sets a single config that is used with our auth module.
  """
  @callback save_config(atom(), any()) :: :ok | :error

  @doc """
  Fetches a config value.
  """
  @callback config(key :: atom(), default :: any()) :: any()

  defmacro __using__(opts) do
    quote bind_quoted: [opts: opts] do
      @behaviour Authex

      @otp_app Keyword.fetch!(opts, :otp_app)
      @table_name :"#{__MODULE__}.Config"

      @impl Authex
      def start_link(config \\ []) do
        config = @otp_app |> Application.get_env(__MODULE__, []) |> Keyword.merge(config)
        {:ok, pid} = GenServer.start_link(__MODULE__, config, name: __MODULE__)
        save_config()

        {:ok, pid}
      end

      @impl Authex
      def init(config) do
        {:ok, config}
      end

      @impl Authex
      def token(claims \\ [], opts \\ []) do
        Authex.Token.new(__MODULE__, claims, opts)
      end

      @impl Authex
      def sign(%Authex.Token{} = token, opts \\ []) do
        __MODULE__
        |> Authex.Signer.new(opts)
        |> Authex.Signer.compact(token)
      end

      @impl Authex
      def verify(compact_token, opts \\ []) do
        Authex.Verifier.run(__MODULE__, compact_token, opts)
      end

      @impl Authex
      def from_token(%Authex.Token{} = token, opts \\ []) do
        serializer = config(:serializer)
        Authex.Serializer.from_token(serializer, token, opts)
      end

      @impl Authex
      def from_compact_token(compact_token, opts \\ []) when is_binary(compact_token) do
        case verify(compact_token, opts) do
          {:ok, token} -> from_token(token, opts)
          error -> error
        end
      end

      @impl Authex
      def for_token(resource, opts \\ []) do
        serializer = config(:serializer)
        Authex.Serializer.for_token(serializer, resource, opts)
      end

      @impl Authex
      def for_compact_token(resource, token_opts \\ [], signer_opts \\ []) do
        with {:ok, token} <- for_token(resource, token_opts) do
          {:ok, sign(token, signer_opts)}
        end
      end

      @impl Authex
      def current_user(%Plug.Conn{private: private}) do
        Map.fetch(private, :authex_current_user)
      end

      @impl Authex
      def current_user(_) do
        :error
      end

      @impl Authex
      def current_scopes(%Plug.Conn{private: private}) do
        case Map.fetch(private, :authex_token) do
          {:ok, token} -> Map.fetch(token, :scopes)
          :error -> :error
        end
      end

      @impl Authex
      def current_scopes(_) do
        :error
      end

      @impl Authex
      def banned?(%Authex.Token{sub: sub}) do
        banlist = config(:banlist, false)
        Authex.Repo.exists?(banlist, sub)
      end

      @impl Authex
      def ban(%Authex.Token{sub: sub}) do
        banlist = config(:banlist, false)
        Authex.Repo.insert(banlist, sub)
      end

      @impl Authex
      def unban(%Authex.Token{sub: sub}) do
        banlist = config(:banlist, false)
        Authex.Repo.delete(banlist, sub)
      end

      @impl Authex
      def blacklisted?(%Authex.Token{jti: jti}) do
        blacklist = config(:blacklist, false)
        Authex.Repo.exists?(blacklist, jti)
      end

      @impl Authex
      def blacklist(%Authex.Token{jti: jti}) do
        blacklist = config(:blacklist, false)
        ttl = Authex.Repo.insert(blacklist, jti)
      end

      @impl Authex
      def unblacklist(%Authex.Token{jti: jti}) do
        blacklist = config(:blacklist, false)
        Authex.Repo.delete(blacklist, jti)
      end

      @impl Authex
      def config(key, default \\ nil) do
        @table_name
        |> Authex.Config.read()
        |> Keyword.get(key, default)
      end

      @impl Authex
      def save_config do
        GenServer.call(__MODULE__, :save_config)
      end

      @impl Authex
      def save_config(config) when is_list(config) do
        GenServer.call(__MODULE__, {:save_config, config})
      end

      @impl Authex
      def save_config(key, value) do
        GenServer.call(__MODULE__, {:save_config, key, value})
      end

      # GenServer callbacks

      def handle_call(:save_config, _from, config) do
        Authex.Config.save(@table_name, config)
        {:reply, :ok, config}
      end

      def handle_call({:save_config, config}, _from, _config) do
        Authex.Config.save(@table_name, config)
        {:reply, :ok, config}
      end

      def handle_call({:save_config, key, value}, _from, old_config) do
        config = Keyword.put(old_config, key, value)
        Authex.Config.save(@table_name, config)
        {:reply, :ok, config}
      end

      defoverridable init: 1
    end
  end
end
