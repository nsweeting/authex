defmodule Authex.Serializer do
  alias Authex.Config
  alias Authex.Serializer
  alias Authex.Token

  @callback handle_from_token(Token.t) :: term | :error

  @callback handle_for_token(term) :: Token.t | :error

  @serializer Config.serializer()

 defmacro __using__(_) do
    quote location: :keep do
      @behaviour Serializer 

      def handle_from_token(_) do
        :error
      end

      def handle_for_token(_) do
        :error
      end

      defoverridable Serializer
    end
  end

  def from_token(%Token{} = token) do
    from_token(@serializer, token)
  end
  def from_token(serializer, %Token{} = token) do
    apply(serializer, :handle_from_token, [token])
  end

  def for_token(resource) do
    for_token(@serializer, resource)
  end
  def for_token(serializer, resource) do
    apply(serializer, :handle_for_token, [resource])
  end

  def for_compact_token(resource) do
    for_compact_token(@serializer, resource)
  end
  def for_compact_token(serializer, resource) do
    case for_token(serializer, resource) do
      :error -> :error
      token  -> Authex.sign(token)
    end
  end
end
