defmodule Authex.Serializer do
  alias Authex.Serializer
  alias Authex.Token

  @callback handle_from_token(Authex.Token.t()) :: term | :error
  @callback handle_for_token(term) :: Authex.Token.t() | :error

  @type serializer :: atom

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

  @doc """
  Takes an `Authex.Token` struct and runs the provided serializer against it.

  ## Parameters

    - serializer: A serializer module.
    - token: An Authex.Token struct.
  """
  @spec from_token(serializer, Authex.Token.t()) :: term
  def from_token(nil, _token) do
    raise Authex.Error, "no serializer configured"
  end

  def from_token(serializer, %Token{} = token) do
    apply(serializer, :handle_from_token, [token])
  end

  @doc """
  Takes a resource and turns it into an `Authex.Token` using the provided serializer.

  ## Parameters

    - serializer: A serializer module.
    - resource: Any data structure the serializer can use.
  """
  @spec for_token(serializer, term) :: Authex.Token.t()
  def for_token(nil, _token) do
    raise Authex.Error, "no serializer configured"
  end

  def for_token(serializer, resource) do
    apply(serializer, :handle_for_token, [resource])
  end
end
