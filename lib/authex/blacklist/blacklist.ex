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

  def get(jti) do
    get(@blacklist, jti)
  end
  def get(module, %Token{jti: jti}) do
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

  def set(jti) do
    get(@blacklist, jti)
  end
  def set(module, %Token{jti: jti}) do
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

  def del(jti) do
    del(@blacklist, jti)
  end
  def del(module, %Token{jti: jti}) do
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
