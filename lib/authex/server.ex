defmodule Authex.Server do
  @moduledoc false

  use GenServer

  @opts_schema KeywordValidator.schema!(
                 secret: [
                   is: :binary,
                   required: true
                 ],
                 blacklist: [
                   is: {:one_of, [:mod, :boolean]},
                   required: true,
                   default: false
                 ],
                 default_alg: [
                   is: {:atom, [:hs256, :hs384, :hs512]},
                   default: :hs256
                 ],
                 default_iss: [
                   is: :binary,
                   required: false
                 ],
                 default_aud: [
                   is: :binary,
                   required: false
                 ],
                 default_ttl: [
                   is: :integer,
                   required: true,
                   default: 3600
                 ],
                 default_sub: [
                   is: {:one_of, [:integer, :binary]},
                   required: false
                 ],
                 default_scopes: [
                   is: {:list, :binary},
                   required: false
                 ],
                 default_jti: [
                   is: {:one_of, [:mfa, :boolean, :binary]},
                   required: true,
                   default: {Authex.UUID, :generate, []}
                 ]
               )

  ################################
  # Public API
  ################################

  @doc false
  def start_link(module, opts \\ [], server_opts \\ []) do
    GenServer.start_link(__MODULE__, {module, opts}, server_opts)
  end

  @doc false
  def config(module, key, default \\ nil) do
    case :ets.lookup(module, key) do
      [{^key, nil} | _] -> default
      [{^key, val} | _] -> val
      _ -> default
    end
  end

  ################################
  # GenServer Callbacks
  ################################

  @doc false
  @impl GenServer
  def init({module, opts}) do
    with {:ok, opts} <- module.init(opts) do
      opts = KeywordValidator.validate!(opts, @opts_schema)
      init_table(module, opts)
      {:ok, module}
    end
  end

  ################################
  # Private API
  ################################

  defp init_table(module, opts) do
    case :ets.info(module) do
      :undefined ->
        :ets.new(module, [:named_table, :public, read_concurrency: true])

      _ ->
        :ok
    end

    for {key, val} <- opts, do: :ets.insert(module, {key, val})

    :ok
  end
end
