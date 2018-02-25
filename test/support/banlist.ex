defmodule Banlist.Test do
  use Agent
  use Authex.Banlist

  def start_link do
    Agent.start_link(fn -> MapSet.new() end, name: __MODULE__)
  end

  def handle_get(sub) do
    __MODULE__
    |> Agent.get(& &1)
    |> MapSet.member?(sub)
  end

  def handle_set(sub) do
    Agent.update(__MODULE__, &MapSet.put(&1, sub))
    :ok
  end

  def handle_del(sub) do
    Agent.update(__MODULE__, &MapSet.delete(&1, sub))
    :ok
  end
end
