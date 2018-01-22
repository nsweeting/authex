defmodule Authex.Banlist do
  alias Authex.Banlist
  alias Authex.Config
  alias Authex.Token

  @doc """
  Checks whether the banlist contains the provided binary sub.

  Returning `true` signals that the sub is banned.

  Returning `false` signals that the sub is not banned.

  Returning `:error` signals an error occured.

  ## Parameters

    - sub: A binary sub.
  """
  @callback handle_get(sub) :: boolean | :error

  @doc """
  Puts the provided binary sub into the banlist.

  Returning `:ok` signals the operation was successful.

  Returning `:error` signals an error occured.

  ## Parameters

    - sub: A binary sub.
  """
  @callback handle_set(sub) :: :ok | :error

  @doc """
  Removes the provided binary sub from the banlist.

  Returning `:ok` signals the operation was successful.

  Returning `:error` signals an error occured.

  ## Parameters

    - sub: A binary sub.
  """
  @callback handle_del(sub) :: :ok | :error

  @type banlist :: atom 
  @type token_or_sub :: Authex.Token.t | binary
  @type sub :: binary 

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
  Takes an Authex.Token struct or binary sub and checks if its banned
  using the default banlist.

  The default banlist is set through the `:banlist` config option.
  
  See get/2 for further details.

  ## Parameters

    - token_or_sub: An Authex.Token struct or binary sub.
  """
  @spec get(token_or_sub) :: :ok | :error
  def get(token_or_sub) do
    Config.banlist() |> get(token_or_sub)
  end

  @doc """
  Takes an Authex.Token struct or binary sub and checks whether it has been
  banned using the provided module.
  
  Returns `false` if the sub is not banned.
  
  Returns `true` if the sub is banned.
  
  Otherwise, returns `:error`.

  ## Parameters

    - banlist:  A banlist module.
    - token_or_sub: An Authex.Token struct or binary sub.
  """
  @spec get(banlist, token_or_sub) :: boolean | :error
  def get(module, %Token{sub: sub}) do
    get(module, sub)
  end

  def get(module, sub) when is_atom(module) and is_binary(sub) do
    case module do
      false     -> :error
      module -> apply(module, :handle_get, [sub])
    end
  end

  def get(_, _) do
    :error
  end

  @doc """
  Takes an Authex.Token struct or binary sub and sets it as being banlisted
  using the default banlist.

  The default banlist is set through the `:banlist` config option.
  
  See set/2 for further details.

  ## Parameters

    - token_or_sub: An Authex.Token struct or binary sub.
  """
  def set(token_or_sub) do
    Config.banlist() |> set(token_or_sub)
  end

  @doc """
  Takes an Authex.Token struct or binary sub and sets it as being banlisted
  using the provided module.
  
  Returns `:ok` if the operation was successful.

  Returns `:error` if an error occured.

  ## Parameters

    - banlist:  A banlist module.
    - token_or_sub: An Authex.Token struct or binary sub.
  """
  @spec set(banlist, token_or_sub) :: :ok | :error
  def set(module, %Token{sub: sub}) do
    set(module, sub)
  end

  def set(module, sub) when is_atom(module) and is_binary(sub) do
    case module do
      false     -> :error
      module -> apply(module, :handle_set, [sub])
    end
  end

  def set(_, _) do
    :error
  end

  @doc """
  Takes an Authex.Token struct or binary sub and deletes it from the banlist
  using the default banlist.

  The default banlist is set through the `:banlist` config option.

  See del/2 for further details.

  ## Parameters

    - token_or_sub: An Authex.Token struct or binary sub.
  """
  @spec del(token_or_sub) :: :ok | :error
  def del(token_or_sub) do
    Config.banlist() |> del(token_or_sub)
  end

  @doc """
  Takes an Authex.Token struct or binary sub and deletes it from the banlist
  using the provided module.
  
  Returns `:ok` if the operation was successful.

  Returns `:error` if an error occured.

  ## Parameters

    - token_or_sub: An Authex.Token struct or binary sub.
  """
  @spec set(banlist, token_or_sub) :: :ok | :error
  def del(module, %Token{sub: sub}) do
    del(module, sub)
  end

  def del(module, sub) when is_atom(module) and is_binary(sub) do
    case module do
      false     -> :error
      module -> apply(module, :handle_del, [sub])
    end
  end

  def del(_, _) do
    :error
  end
end
