defmodule Authex.Blacklist do
  alias Authex.Blacklist
  alias Authex.Config
  alias Authex.Token

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

  @type blacklist :: atom 
  @type token_or_jti :: Authex.Token.t | binary
  @type jti :: binary 

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
  Takes an Authex.Token struct or binary jti and checks if its blacklisted
  using the default blacklist.

  The default blacklist is set through the `:blacklist` config option.
  
  See get/2 for further details.

  ## Parameters

    - token_or_jti: An Authex.Token struct or binary jti.
  """
  @spec get(token_or_jti) :: :ok | :error
  def get(token_or_jti) do
    Config.blacklist() |> get(token_or_jti)
  end

  @doc """
  Takes an Authex.Token struct or binary jti and checks whether it has been
  blacklisted using the provided module.
  
  Returns `false` if the jti is not blacklisted.
  
  Returns `true` if it has been blacklisted.
  
  Otherwise, returns `:error`.

  ## Parameters

    - blacklist:  A blacklist module.
    - token_or_jti: An Authex.Token struct or binary jti.
  """
  @spec get(blacklist, token_or_jti) :: boolean | :error
  def get(module, %Token{jti: jti} = _token_or_jti) do
    get(module, jti)
  end
  def get(module, jti) when is_atom(module) and is_binary(jti) do
    case module do
      false     -> :error
      module -> apply(module, :handle_get, [jti])
    end
  end
  def get(_, _) do
    :error
  end

  @doc """
  Takes an Authex.Token struct or binary jti and sets it as being blacklisted
  using the default blacklist.

  The default blacklist is set through the `:blacklist` config option.
  
  See set/2 for further details.

  ## Parameters

    - token_or_jti: An Authex.Token struct or binary jti.
  """
  def set(token_or_jti) do
    Config.blacklist() |> set(token_or_jti)
  end

  @doc """
  Takes an Authex.Token struct or binary jti and sets it as being blacklisted
  using the provided module.
  
  Returns `:ok` if the operation was successful.

  Returns `:error` if an error occured.

  ## Parameters

    - blacklist:  A blacklist module.
    - token_or_jti: An Authex.Token struct or binary jti.
  """
  @spec set(blacklist, token_or_jti) :: :ok | :error
  def set(module, %Token{jti: jti} = _token_or_jti) do
    set(module, jti)
  end
  def set(module, jti) when is_atom(module) and is_binary(jti) do
    case module do
      false     -> :error
      module -> apply(module, :handle_set, [jti])
    end
  end
  def set(_, _) do
    :error
  end

  @doc """
  Takes an Authex.Token struct or binary jti and deletes it from the blacklist
  using the default blacklist.

  The default blacklist is set through the `:blacklist` config option.

  See del/2 for further details.

  ## Parameters

    - token_or_jti: An Authex.Token struct or binary jti.
  """
  @spec del(token_or_jti) :: :ok | :error
  def del(token_or_jti) do
    Config.blacklist() |> del(token_or_jti)
  end

  @doc """
  Takes an Authex.Token struct or binary jti and deletes it from the blacklist
  using the provided module.
  
  Returns `:ok` if the operation was successful.

  Returns `:error` if an error occured.

  ## Parameters

    - token_or_jti: An Authex.Token struct or binary jti.
  """
  @spec set(blacklist, token_or_jti) :: :ok | :error
  def del(module, %Token{jti: jti} = _token_or_jti) do
    del(module, jti)
  end
  def del(module, jti) when is_atom(module) and is_binary(jti) do
    case module do
      false     -> :error
      module -> apply(module, :handle_del, [jti])
    end
  end
  def del(_, _) do
    :error
  end
end
