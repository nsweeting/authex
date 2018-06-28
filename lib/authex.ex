defmodule Authex do
  alias Authex.Banlist
  alias Authex.Blacklist
  alias Authex.Signer
  alias Authex.Serializer
  alias Authex.Token
  alias Authex.Verifier

  @type token_or_sub :: Authex.Token.t() | binary | integer

  @type token_or_jti :: Authex.Token.t() | binary

  @doc """
  Creates a new token from the given claims and options.

  Returns an `Authex.Token` struct.

  ## Parameters

    - claims: A keyword list of JWT claims.
    - options: A keyword list of options.

  ## Options
    * `:time` - the base time (timestamp format) in which to use.
    * `:ttl` - the TTL for the token.
  """
  @callback token(claims :: Authex.Token.claims(), options :: Authex.Token.options()) ::
              token :: Authex.Token.t()

  @doc """
  Signs an `Authex.Token` struct, creating a compact token.

  Returns a binary compact token.

  ## Parameters

    - token: An `Authex.Token` struct.
    - options: A keyword list of options.

  ## Options
    * `:secret` - the secret key to sign the token with.
    * `:alg` - the algorithm to sign the token with.
  """
  @callback sign(token :: Authex.Token.t(), options :: Authex.Signer.options()) ::
              compact_token :: Authex.Token.compact() | no_return

  @doc """
  Verifies a compact token.

  Returns `{:ok, %Authex.Token{}}` if the token is valid.

  Otherwise, returns `{:error, :reason}`

  ## Parameters

    - compact_token: A compact token binary.
    - options: A keyword list of options.

  ## Options
    * `:time` - the base time (timestamp format) in which to use.
    * `:secret` - the secret key to verify the token with.
    * `:alg` - the algorithm to verify the token with.
    * `:banlist` - the banlist module to verify with.
    * `:blacklist` - the blacklist module to verify with.
  """
  @callback verify(
              compact_token :: Authex.Token.compact(),
              options :: Authex.Verification.options()
            ) :: {:ok, token :: Authex.Token.t()} | {:error, atom}

  @doc """
  Turns an `Authex.Token` into a usable data structure using a serializer module.

  Returns any term defined by the serializer.

  Otherwise, returns `:error`.

  ## Parameters

    - token: An `Authex.Token` struct.
  """
  @callback from_token(token :: Authex.Token.t()) :: any | {:error, atom}

  @doc """
  Turns a compact token into a usable data structure using a serializer module.

  Returns any term defined by the serializer.

  Otherwise, returns `:error`.

  ## Parameters

    - compact_token: A binary compact token.
  """
  @callback from_compact_token(
              compact_token :: Authex.Token.compact(),
              options :: Authex.Signer.options()
            ) :: any | {:error, atom}

  @doc """
  Turns a usable data structure into an `Authex.Token` using a serializer module.

  Returns a `Authex.Token` struct.

  ## Parameters

    - resource: Any usable data structure.
  """
  @callback for_token(any) :: Authex.Token.t() | :error

  @doc """
  Turns a usable data structure into a compact token using a serializer module.

  Returns a binary compact token.

  ## Parameters

    - resource: Any usable data structure.
  """
  @callback for_compact_token(any) :: Authex.Token.compact() | :error

  @doc """
  Gets the current user from a Plug.Conn.

  Returns a term defined by a serializer.

  ## Parameters

    - conn: A Plug.Conn struct.
  """
  @callback current_user(Plug.Conn.t()) :: {:ok, any} | :error

  @doc """
  Gets the current scopes from a Plug.Conn.

  Returns a list of scopes.

  ## Parameters

    - conn: A Plug.Conn struct.
  """
  @callback current_scopes(Plug.Conn.t()) :: {:ok, list} | :error

  @doc """
  Checks whether a subject is banned.

  Returns a boolean

  ## Parameters

    - token_or_sub: An `Authex.Token` or binary subject.
  """
  @callback banned?(token_or_sub) :: boolean

  @doc """
  Bans a subject.

  ## Parameters

    - token_or_sub: An `Authex.Token` or binary subject.
  """
  @callback ban(token_or_sub) :: :ok | :error

  @doc """
  Unbans a subject.

  ## Parameters

    - token_or_sub: An `Authex.Token` or binary subject.
  """
  @callback unban(token_or_sub) :: :ok | :error

  @doc """
  Checks whether a jti is blacklisted.

  Returns a boolean

  ## Parameters

    - token_or_jti: An `Authex.Token` or binary jti.
  """
  @callback blacklisted?(token_or_jti) :: boolean

  @doc """
  Blacklists a jti.

  ## Parameters

    - token_or_jti: An `Authex.Token` or binary jti.
  """
  @callback blacklist(token_or_jti) :: :ok | :error

  @doc """
  Unblacklists a jti.

  ## Parameters

    - token_or_jti: An `Authex.Token` or binary jti.
  """
  @callback unblacklist(token_or_jti) :: :ok | :error

  @doc """
  Sets the secret key that will be used to sign our tokens with.

  ## Parameters

    - secret: A binary secret.
  """
  @callback set_secret(binary) :: :ok

  @doc """
  Fetches a config value.

  ## Parameters

    - key: A binary secret.
    - default: A default value if none is present.
  """
  @callback config(key :: atom, default :: any) :: any

  @type t :: module

  defmacro __using__(opts) do
    quote bind_quoted: [opts: opts] do
      @otp_app Keyword.fetch!(opts, :otp_app)

      def token(claims \\ [], opts \\ []) do
        Token.new(__MODULE__, claims, opts)
      end

      def sign(%Token{} = token, opts \\ []) do
        __MODULE__
        |> Signer.new(opts)
        |> Signer.compact(token)
      end

      def verify(compact_token, opts \\ []) do
        Verifier.run(__MODULE__, compact_token, opts)
      end

      def from_token(%Token{} = token) do
        serializer = config(:serializer)
        Serializer.from_token(serializer, token)
      end

      def from_compact_token(compact_token, opts \\ []) when is_binary(compact_token) do
        case verify(compact_token, opts) do
          {:ok, token} -> from_token(token)
          error -> error
        end
      end

      def for_token(resource) do
        serializer = config(:serializer)
        Serializer.for_token(serializer, resource)
      end

      def for_compact_token(resource, opts \\ []) do
        resource
        |> for_token()
        |> sign(opts)
      end

      def current_user(%Plug.Conn{private: private}) do
        Map.fetch(private, :authex_current_user)
      end

      def current_user(_) do
        :error
      end

      def current_scopes(%Plug.Conn{private: private}) do
        case Map.fetch(private, :authex_token) do
          {:ok, token} -> Map.fetch(token, :scopes)
          :error -> :error
        end
      end

      def current_scopes(_) do
        :error
      end

      def banned?(token_or_sub) do
        banlist = config(:banlist, false)
        Banlist.get(banlist, token_or_sub)
      end

      def ban(token_or_sub) do
        banlist = config(:banlist, false)
        Banlist.set(banlist, token_or_sub)
      end

      def unban(token_or_sub) do
        banlist = config(:banlist, false)
        Banlist.del(banlist, token_or_sub)
      end

      def blacklisted?(token_or_jti) do
        blacklist = config(:blacklist, token_or_jti)
        Blacklist.get(blacklist, token_or_jti)
      end

      def blacklist(token_or_jti) do
        blacklist = config(:blacklist, false)
        Blacklist.set(blacklist, token_or_jti)
      end

      def unblacklist(token_or_jti) do
        blacklist = config(:blacklist, false)
        Blacklist.del(blacklist, token_or_jti)
      end

      def set_secret(secret) do
        config =
          @otp_app
          |> Application.get_env(__MODULE__, [])
          |> Keyword.put(:secret, secret)

        Application.put_env(@otp_app, __MODULE__, config)
      end

      def config(key, default \\ nil) do
        @otp_app
        |> Application.get_env(__MODULE__, [])
        |> Keyword.get(key, default)
      end
    end
  end
end
