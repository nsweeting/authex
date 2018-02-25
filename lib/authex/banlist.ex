defmodule Authex.Banlist do
  alias Authex.Banlist
  alias Authex.Token

  @type t :: module
  @type sub :: binary | integer
  @type token_or_sub :: Authex.Token.t() | sub

  @doc """
  Checks whether the banlist contains the provided binary or integer sub.

  Returning `true` signals that the sub is banned.

  Returning `false` signals that the sub is not banned.

  Returning `:error` signals an error occured.

  ## Parameters

    - sub: A binary or integer sub.
  """
  @callback handle_get(sub) :: boolean | :error

  @doc """
  Puts the provided binary sub into the banlist.

  Returning `:ok` signals the operation was successful.

  Returning `:error` signals an error occured.

  ## Parameters

    - sub: A binary or integer sub.
  """
  @callback handle_set(sub) :: :ok | :error

  @doc """
  Removes the provided binary or integer sub from the banlist.

  Returning `:ok` signals the operation was successful.

  Returning `:error` signals an error occured.

  ## Parameters

    - sub: A binary or integer sub.
  """
  @callback handle_del(sub) :: :ok | :error

  defmacro __using__(_) do
    quote location: :keep do
      @behaviour Banlist

      @doc false
      def handle_get(_sub) do
        :error
      end

      @doc false
      def handle_set(_sub) do
        :error
      end

      @doc false
      def handle_del(_sub) do
        :error
      end

      defoverridable Banlist
    end
  end

  @doc """
  Takes an `Authex.Token` struct or binary or integer sub and checks whether it has been
  banned using the provided module.

  Returns `false` if the sub is not banned.

  Returns `true` if the sub is banned.

  Otherwise, returns `:error`.

  ## Parameters

    - banlist: A banlist module.
    - token_or_sub: An `Authex.Token` struct or binary or integer sub.
  """
  @spec get(banlist :: Authex.Banlist.t(), token_or_sub) :: boolean | :error
  def get(banlist, %Token{sub: sub}) do
    get(banlist, sub)
  end

  def get(banlist, sub) do
    do_action(banlist, :handle_get, sub)
  end

  @doc """
  Takes an `Authex.Token` struct or binary or integer sub and sets it as being banned
  using the provided module.

  Returns `:ok` if the operation was successful.

  Returns `:error` if an error occured.

  ## Parameters

    - banlist:  A banlist module.
    - token_or_sub: An `Authex.Token` struct or binary or integer sub.
  """
  @spec set(banlist :: Authex.Banlist.t(), token_or_sub) :: :ok | :error
  def set(banlist, %Token{sub: sub}) do
    set(banlist, sub)
  end

  def set(banlist, sub) do
    do_action(banlist, :handle_set, sub)
  end

  @doc """
  Takes an `Authex.Token` struct or binary or integer sub and deletes it from the banlist
  using the provided module.

  Returns `:ok` if the operation was successful.

  Returns `:error` if an error occured.

  ## Parameters

    - banlist:  A banlist module.
    - token_or_sub: An `Authex.Token` struct or binary or integer sub.
  """
  @spec del(banlist :: Authex.Banlist.t(), token_or_sub) :: :ok | :error
  def del(banlist, %Token{sub: sub}) do
    del(banlist, sub)
  end

  def del(banlist, sub) do
    do_action(banlist, :handle_del, sub)
  end

  defp do_action(banlist, action, sub) do
    case banlist do
      false -> :error
      module -> apply(module, action, [sub])
    end
  end
end
