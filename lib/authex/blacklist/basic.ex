defmodule Authex.Blacklist.Basic do
  use Agent
  use Authex.Blacklist

  def start_link do
    Agent.start_link(fn -> MapSet.new() end, name: __MODULE__)
  end

  def get(jti) do
    Agent.get(__MODULE__, &MapSet.member?(&1, jti))
  end

  def set(jti) do
    Agent.update(__MODULE__, &MapSet.put(&1, jti))
  end

  def del(jti) do
    Agent.update(__MODULE__, &MapSet.delete(&1, jti))
  end
end
