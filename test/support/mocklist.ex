defmodule Mocklist do
  use Authex.Repo
  use Agent

  @impl Authex.Repo
  def start_link(_opts \\ []) do
    Agent.start_link(fn -> MapSet.new() end, name: __MODULE__)
  end

  @impl Authex.Repo
  def exists?(key) do
    __MODULE__
    |> Agent.get(& &1)
    |> MapSet.member?(key)
  end

  @impl Authex.Repo
  def insert(key) do
    Agent.update(__MODULE__, &MapSet.put(&1, key))
    :ok
  end

  @impl Authex.Repo
  def delete(key) do
    Agent.update(__MODULE__, &MapSet.delete(&1, key))
    :ok
  end
end
