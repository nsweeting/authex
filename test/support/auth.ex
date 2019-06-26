defmodule Auth do
  use Authex

  @doc false
  def start_link(opts \\ []) do
    Authex.start_link(__MODULE__, opts)
  end

  @doc false
  @impl Authex
  def init(opts) do
    opts = Keyword.put_new(opts, :secret, "foo")
    {:ok, opts}
  end

  @doc false
  @impl Authex
  def handle_for_token(%{id: id, scopes: scopes}, opts) do
    {:ok, [sub: id, scopes: scopes], opts}
  end

  def handle_for_token(%{id: id}, opts) do
    {:ok, [sub: id], opts}
  end

  @doc false
  @impl Authex
  def handle_from_token(%Authex.Token{sub: sub, scopes: scopes}, _opts) do
    {:ok, %{id: sub, scopes: scopes}}
  end
end
