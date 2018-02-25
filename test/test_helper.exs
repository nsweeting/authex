defmodule Authex.TestHelpers do
  def set_config(opts) do
    Application.put_env(:authex, Auth.Test, opts)
  end

  def reset_config do
    set_config([])
  end
end

ExUnit.start()
