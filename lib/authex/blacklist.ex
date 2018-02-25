defmodule Authex.Blacklist do
  alias Authex.Blacklist
  alias Authex.Token

  @type t :: module
  @type jti :: binary
  @type token_or_jti :: Authex.Token.t() | jti

  @doc """
  Checks whether the blacklist contains the provided binary jti.

  Returning `true` signals that the jti is blacklisted.

  Returning `false` signals that the jti is not blacklisted.

  Returning `:error` signals an error occured.

  ## Parameters

    - jti: A binary jti.
  """
  @callback handle_get(jti) :: boolean | :error

  @doc """
  Puts the provided binary jti into the blacklist.

  Returning `:ok` signals the operation was successful.

  Returning `:error` signals an error occured.

  ## Parameters

    - jti: A binary jti.
  """
  @callback handle_set(jti) :: :ok | :error

  @doc """
  Removes the provided binary jti from the blacklist.

  Returning `:ok` signals the operation was successful.

  Returning `:error` signals an error occured.

  ## Parameters

    - jti: A binary jti.
  """
  @callback handle_del(jti) :: :ok | :error

  defmacro __using__(_) do
    quote location: :keep do
      @behaviour Blacklist

      @doc false
      def handle_get(_jti) do
        :error
      end

      @doc false
      def handle_set(_jti) do
        :error
      end

      @doc false
      def handle_del(_jti) do
        :error
      end

      defoverridable Blacklist
    end
  end

  @doc """
  Takes an `Authex.Token` struct or binary jti and checks whether it has been
  blacklisted using the provided module.

  Returns `false` if the jti is not blacklisted.

  Returns `true` if the jti is blacklisted.

  Otherwise, returns `:error`.

  ## Parameters

    - blacklist:  A blacklist module.
    - token_or_jti: An `Authex.Token` struct or binary or integer jti.
  """
  @spec get(blacklist :: Authex.Blacklist.t(), token_or_jti) :: boolean | :error
  def get(blacklist, %Token{jti: jti}) do
    get(blacklist, jti)
  end

  def get(blacklist, jti) do
    do_action(blacklist, :handle_get, jti)
  end

  @doc """
  Takes an `Authex.Token` struct or binary jti and sets it as being blacklisted
  using the provided module.

  Returns `:ok` if the operation was successful.

  Returns `:error` if an error occured.

  ## Parameters

    - blacklist:  A blacklist module.
    - token_or_jti: An `Authex.Token` struct or binary or integer jti.
  """
  @spec set(blacklist :: Authex.Blacklist.t(), token_or_jti) :: :ok | :error
  def set(blacklist, %Token{jti: jti}) do
    set(blacklist, jti)
  end

  def set(blacklist, jti) do
    do_action(blacklist, :handle_set, jti)
  end

  @doc """
  Takes an `Authex.Token` struct or binary jti and deletes it from the blacklist
  using the provided module.

  Returns `:ok` if the operation was successful.

  Returns `:error` if an error occured.

  ## Parameters

    - blacklist:  A blacklist module.
    - token_or_jti: An Authex.Token struct or binary or integer jti.
  """
  @spec del(blacklist :: Authex.Blacklist.t(), token_or_jti) :: :ok | :error
  def del(blacklist, %Token{jti: jti}) do
    del(blacklist, jti)
  end

  def del(blacklist, jti) do
    do_action(blacklist, :handle_del, jti)
  end

  defp do_action(blacklist, action, jti) do
    case blacklist do
      false -> :error
      module -> apply(module, action, [jti])
    end
  end
end
