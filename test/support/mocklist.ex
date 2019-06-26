defmodule Mocklist do
  @behaviour Authex.Repo

  use Agent

  @doc false
  def start_link(_opts \\ []) do
    Agent.start_link(fn -> MapSet.new() end, name: __MODULE__)
  end

  @doc false
  @impl Authex.Repo
  def exists?(key) do
    __MODULE__
    |> Agent.get(& &1)
    |> MapSet.member?(key)
  end

  @doc false
  @impl Authex.Repo
  def insert(key) do
    Agent.update(__MODULE__, &MapSet.put(&1, key))
    :ok
  end

  @doc false
  @impl Authex.Repo
  def delete(key) do
    Agent.update(__MODULE__, &MapSet.delete(&1, key))
    :ok
  end
end
