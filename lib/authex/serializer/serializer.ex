defmodule Authex.Serializer do
  alias Authex.Config
  alias Authex.Serializer
  alias Authex.Token

  @callback from_token(Token.t) :: term | :error

  @callback for_token(term) :: Token.t | :error

  @serializer Config.serializer()

 defmacro __using__(_) do
    quote location: :keep do
      @behaviour Serializer 

      def from_token(_) do
        :error
      end

      def for_token(_) do
        :error
      end

      defoverridable Serializer
    end
  end

  def from_token(%Token{} = token, serializer \\ @serializer) do
    apply(serializer, :from_token, [token])
  end

  def for_token(resource, serializer \\ @serializer) do
    apply(serializer, :for_token, [resource])
  end

  def for_compact_token(resource, serializer \\ @serializer) do
    case for_token(resource, serializer) do
      :error -> :error
      token  -> Authex.sign(token)
    end
  end
end
