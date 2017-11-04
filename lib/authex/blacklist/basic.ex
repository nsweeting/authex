defmodule Authex.Blacklist.Basic do
  use Authex.Blacklist
  use Agent

  def start_link do
    Agent.start_link(fn -> MapSet.new() end, name: __MODULE__)
  end

  def handle_get(jti) do
    Agent.get(__MODULE__, &MapSet.member?(&1, jti))
  end

  def handle_set(jti) do
    Agent.update(__MODULE__, &MapSet.put(&1, jti))
  end

  def handle_del(jti) do
    Agent.update(__MODULE__, &MapSet.delete(&1, jti))
  end
end
