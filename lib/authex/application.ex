defmodule Authex.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  def start(_type, args) do
    # List all child processes to be supervised
    children = build_children(args)

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Authex.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # WIP
  defp build_children(_args) do
    []
  end
end
