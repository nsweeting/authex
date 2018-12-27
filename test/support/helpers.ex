defmodule Authex.TestHelpers do
  def save_config(config) do
    Auth.save_config(config)
  end

  def reset_config do
    Auth.save_config([])
  end
end
