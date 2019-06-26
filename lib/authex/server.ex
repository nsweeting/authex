defmodule Authex.Server do
  @moduledoc false

  use GenServer

  @opts_schema %{
    secret: [type: :binary, required: true],
    blacklist: [type: [:module, :boolean], required: true, default: false],
    default_alg: [
      type: :atom,
      inclusion: [:hs256, :hs384, :hs512],
      required: true,
      default: :hs256
    ],
    default_iss: [type: :binary, required: false],
    default_aud: [type: :binary, required: false],
    default_ttl: [type: :integer, required: true, default: 3600],
    default_sub: [type: [:integer, :binary], required: false],
    default_scopes: [type: {:list, :binary}, required: false],
    default_jti: [
      type: [:mfa, :boolean, :binary],
      required: true,
      default: {Authex.UUID, :generate, []}
    ]
  }

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
