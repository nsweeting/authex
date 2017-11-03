defmodule Authex.Blacklist do
  alias Authex.Blacklist
  alias Authex.Config
  alias Authex.Token

  @callback get(binary) :: boolean | :error
  @callback set(binary) :: :ok | :error
  @callback del(binary) :: :ok | :error

  @blacklist Config.blacklist()

  defmacro __using__(_) do
    quote location: :keep do
      @behaviour Blacklist

      def get(_) do
        :error
      end

      def set(_) do
        :error
      end

      def del(_) do
        :error
      end

      defoverridable Blacklist
    end
  end

  def get(_, blacklist \\ @blacklist)
  def get(%Token{jti: jti}, blacklist) do
    get(jti, blacklist)
  end
  def get(jti, blacklist) when is_binary(jti) and is_atom(blacklist) do
    case blacklist do
      false     -> :error
      blacklist -> apply(blacklist, :get, [jti])
    end
  end
  def get(_, _) do
    :error
  end

  def set(_, blacklist \\ @blacklist)
  def set(%Token{jti: jti}, blacklist) do
    set(jti, blacklist)
  end
  def set(jti, blacklist) when is_binary(jti) and is_atom(blacklist) do
    case blacklist do
      false     -> :error
      blacklist -> apply(blacklist, :set, [jti])
    end
  end
  def set(_, _) do
    :error
  end

  def del(_, blacklist \\ @blacklist)
  def del(%Token{jti: jti}, blacklist) do
    del(jti, blacklist)
  end
  def del(jti, blacklist) when is_binary(jti) and is_atom(blacklist) do
    case blacklist do
      false     -> :error
      blacklist -> apply(blacklist, :del, [jti])
    end
  end
  def del(_, _) do
    :error
  end
end
