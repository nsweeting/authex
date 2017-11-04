defmodule Authex.Serializer do
  alias Authex.Config
  alias Authex.Serializer
  alias Authex.Token

  @callback handle_from_token(Authex.Token.t) :: term | :error
  @callback handle_for_token(term) :: Authex.Token.t | :error

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
  Takes an Authex.Token struct and runs the default serializer against it.

  ## Parameters

    - token: An Authex.Token struct.

  ## Examples

      iex> [sub: 1, scopes: []] |> Authex.token() |> Authex.Serializer.from_token()
      %{id: 1, scopes: []}
  """
  @spec from_token(Authex.Token.t) :: term
  def from_token(%Token{} = token) do
    Config.serializer() |> from_token(token)
  end

  @doc """
  Takes an Authex.Token struct and runs the provided serializer against it.

  ## Parameters

    - serializer: A serializer module.
    - token: An Authex.Token struct.

  ## Examples

      iex> token = Authex.token([sub: 1, scopes: []])
      iex> Authex.Serializer.from_token(Authex.Serializer.Basic, token)
      %{id: 1, scopes: []}
  """
  @spec from_token(serializer, Authex.Token.t) :: term
  def from_token(serializer, %Token{} = token) do
    apply(serializer, :handle_from_token, [token])
  end

  @doc """
  Takes a resource and turns it into an Authex.Token using the default serializer.

  ## Parameters

    - resource: Any data structure the serializer can use.

  ## Examples

      iex> token = Authex.Serializer.for_token(%{id: 1, scopes: ["test/read"]})
      iex> with %Authex.Token{sub: sub, scopes: scopes} <- token, do: [sub, scopes]
      [1, ["test/read"]]
  """
  @spec for_token(term) :: Authex.Token.t
  def for_token(resource) do
    Config.serializer() |> for_token(resource)
  end

  @doc """
  Takes a resource and turns it into an Authex.Token using the provided serializer.

  ## Parameters

    - serializer: A serializer module.
    - resource: Any data structure the serializer can use.

  ## Examples

      iex> token = Authex.Serializer.for_token(Authex.Serializer.Basic, %{id: 1, scopes: ["test/read"]})
      iex> with %Authex.Token{sub: sub, scopes: scopes} <- token, do: [sub, scopes]
      [1, ["test/read"]]
  """
  @spec for_token(serializer, term) :: Authex.Token.t
  def for_token(serializer, resource) do
    apply(serializer, :handle_for_token, [resource])
  end

  @doc """
  Takes a resource and turn it into a compact token using the default serializer module.

  ## Parameters

    - resource: Any usable data structure.

  ## Examples

      iex> %{id: 1} |> Authex.Serializer.for_compact_token() |> is_binary()
      true
  """
  @spec for_compact_token(term) :: binary
  def for_compact_token(resource) do
    Config.serializer() |> for_compact_token(resource)
  end


  @doc """
  Takes a resource and turn it into a compact token using the provided serializer module.

  ## Parameters

    - resource: Any usable data structure.

  ## Examples

      iex> compact = Authex.Serializer.for_compact_token(Authex.Serializer.Basic, %{id: 1})
      iex> is_binary(compact)
      true
  """
  @spec for_compact_token(serializer, term) :: binary
  def for_compact_token(serializer, resource) do
    case for_token(serializer, resource) do
      :error -> :error
      token  -> Authex.sign(token)
    end
  end
end
