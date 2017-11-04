defmodule Authex.Blacklist do
  alias Authex.Blacklist
  alias Authex.Config
  alias Authex.Token

  @callback handle_get(binary) :: boolean | :error
  @callback handle_set(binary) :: :ok | :error
  @callback handle_del(binary) :: :ok | :error

  @blacklist Config.blacklist()

  defmacro __using__(_) do
    quote location: :keep do
      @behaviour Blacklist

      def handle_get(_) do
        :error
      end

      def handle_set(_) do
        :error
      end

      def handle_del(_) do
        :error
      end

      defoverridable Blacklist
    end
  end

  @doc """
  Takes an Authex.Token struct or binary jti and checks whether it has been
  blacklisted or not using the default blacklist. See get/2 for further details.

  ## Parameters

    - token_or_jti: An Authex.Token struct or binary jti.
  """
  def get(token_or_jti) do
    get(@blacklist, token_or_jti)
  end

  @doc """
  Takes an Authex.Token struct or binary jti and checks whether it has been
  blacklisted or not using the provided blacklist. Returns `false` if the jti
  is not blacklisted. Returns `true` if it has been blacklisted. Otherwise,
  returns `:error`.

  ## Parameters

    - blacklist:  A blacklist module.
    - token_or_jti: An Authex.Token struct or binary jti.
  """
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
  using the default blacklist. See set/2 for further details.

  ## Parameters

    - token_or_jti: An Authex.Token struct or binary jti.
  """
  def set(token_or_jti) do
    get(@blacklist, token_or_jti)
  end

  @doc """
  Takes an Authex.Token struct or binary jti and sets it as being blacklisted
  using the default blacklist. Returns `:ok` if the action was successful.
  Otherwise, `:error`.

  ## Parameters

    - blacklist:  A blacklist module.
    - token_or_jti: An Authex.Token struct or binary jti.
  """
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
  using the default blacklist. See del/2 for further details.

  ## Parameters

    - token_or_jti: An Authex.Token struct or binary jti.
  """
  def del(token_or_jti) do
    del(@blacklist, token_or_jti)
  end

  @doc """
  Takes an Authex.Token struct or binary jti and deletes it from the blacklist
  using the default blacklist. Returns `:ok` if the action was successful.
  Otherwise, `:error`.

  ## Parameters

    - token_or_jti: An Authex.Token struct or binary jti.
  """
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
