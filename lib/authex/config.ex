defmodule Authex.Config do
  @moduledoc false

  alias :ets, as: ETS

  @doc false
  def save(table_name, config) do
    if ETS.info(table_name) == :undefined do
      ETS.new(table_name, [:named_table, :protected, read_concurrency: true])
    end

    ETS.insert(table_name, {:config, config})

    :ok
  end

  @doc false
  def read(table_name) do
    case ETS.lookup(table_name, :config) do
      [{:config, config} | _] ->
        config

      _ ->
        :error
    end
  end
end
