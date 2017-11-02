defmodule Authex.Serializer do
  alias Authex.Config
  alias Authex.Serializer
  alias Authex.Token

  @callback from_token(Token.t) :: term | :error

  @callback for_token(term) :: Token.t | :error

 defmacro __using__(_) do
    quote location: :keep do
      @behaviour Serializer 

      def from_token(%Token{sub: sub, scopes: scopes}) do
        %{id: sub, scopes: scopes}
      end
      def from_token(_) do
        :error
      end

      def for_token(%{id: id}) do
        Token.new([sub: id], [])
      end
      def for_token(_) do
        :error
      end

      defoverridable Serializer
    end
  end

  def from_token(token) do
    apply(Config.serializer(), :from_token, [token])
  end

  def for_token(resource) do
    apply(Config.serializer(), :for_token, [resource])
  end
end
