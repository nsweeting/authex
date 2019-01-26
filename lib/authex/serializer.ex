defmodule Authex.Serializer do
  @moduledoc """
  Defines a serializer.

  A serializer is used to convert a resource into a token, as well as a token
  back into a resource. A typical resource would be something like a user struct.

      defmodule MyApp.Auth.UserSerializer do
        use Authex.Serializer

        @impl Authex.Serializer
        def for_token(user, opts) do
          token = MyApp.Auth.token([sub: user.id, scopes: user.scopes], opts)
          {:ok, token}
        end

        @impl Authex.Serializer
        def from_token(token, _opts) do
          {:ok, %MyApp.User{id: token.sub, scopes: token.scopes}}
        end
      end

  With our serializer defined, we must add callbacks for `c:for_token/2` to
  convert our user into a token, as well as for `c:from_token/2` to convert a
  token into a user
  """

  @doc """
  Converts a resource into an `Authex.Token` struct.

  Must return `{:ok, token}` on success.

  ## Options
    * `:time` - The base time (timestamp format) in which to use.
    * `:ttl` - The time-to-live for the token in seconds. The lifetime is based
    on the time provided via the options, or the current time if not provided.
  """
  @callback for_token(term(), options :: Authex.Token.options()) ::
              {:ok, Authex.Token.t()} | {:error, any()}

  @doc """
  Converts an `Authex.Token` struct into a resource.

  Must return `{:ok, resource}` on success.

  ## Options

  Any additional options that your serializer might need.
  """
  @callback from_token(token :: Authex.Token.t(), options :: keyword()) ::
              {:ok, term()} | {:error, term()}

  @type t :: module()

  defmacro __using__(_) do
    quote location: :keep do
      @behaviour Authex.Serializer

      def for_token(_, _) do
        {:error, :not_implemented}
      end

      def from_token(_, _) do
        {:error, :not_implemented}
      end

      defoverridable Authex.Serializer
    end
  end

  @doc false
  @spec for_token(serializer :: Authex.Serializer.t(), term(), options :: Authex.Token.options()) ::
          {:ok, Authex.Token.t()} | {:error, term()}
  def for_token(nil, _token, _opts) do
    {:error, :no_serializer}
  end

  def for_token(serializer, resource, opts) do
    apply(serializer, :for_token, [resource, opts])
  end

  @doc false
  @spec from_token(
          serializer :: Authex.Serializer.t(),
          token :: Authex.Token.t(),
          options :: keyword()
        ) :: {:ok, term()} | {:error, term()}
  def from_token(nil, _token, _opts) do
    {:error, :no_serializer}
  end

  def from_token(serializer, token, opts) do
    apply(serializer, :from_token, [token, opts])
  end
end
