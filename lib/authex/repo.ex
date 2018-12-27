defmodule Authex.Repo do
  @moduledoc """
  Defines a verification repo.

  This allows for the creation of persistent storage for blacklists and banlists.
  Blacklists are used to block usage of a token by its `:jti` key. Banlists are
  used to block usage of a token by its `:sub` key.

      defmodule MyApp.Auth.Banlist do
        use Authex.Repo

        @impl Authex.Repo
        def start_link(config) do
          # Start the repo process if required.
        end

        @impl Authex.Repo
        def init(config) do
          # Perform any dynamic config.
        end

        @impl Authex.Repo
        def exists?(key) do
          # Check if the key exists in the repo.
        end

        @impl Authex.Repo
        def insert(key) do
          # Insert the key in the repo.
        end

        @impl Authex.Repo
        def delete(key) do
          # Delete the key from the repo.
        end
      end

  Please be aware of the performance penalty that may be incurred if using blacklists
  and banlists during the auth verification process. This will largely depend on
  the storage medium used.
  """

  @type t :: module() | false

  @type key :: binary() | integer()

  @doc """
  Starts the repo process.

  Returns `{:ok, pid}` on success.

  Returns `{:error, {:already_started, pid}}` if the repo process is already
  started or `{:error, term}` in case anything else goes wrong.
  """
  @callback start_link(config :: Keyword.t()) :: GenServer.on_start()

  @doc """
  A callback executed when the repo process starts.

  This should be used to dynamically set any config during runtime.

  Returns `{:ok, config}`
  """
  @callback init(config :: Keyword.t()) :: {:ok, Keyword.t()}

  @doc """
  Checks if a binary key exists in the repo.

  Returns a boolean, or `:error`
  """
  @callback exists?(key()) :: boolean() | :error

  @doc """
  Inserts a binary key into the repo.

  Returns `:ok` on success, or `:error` on error.
  """
  @callback insert(key()) :: :ok | :error

  @doc """
  Deletes a binary key from the repo.

  Returns `:ok` on success, or `:error` on error.
  """
  @callback delete(key()) :: :ok | :error

  defmacro __using__(_) do
    quote location: :keep do
      @behaviour Authex.Repo

      @impl Authex.Repo
      def start_link(_config) do
        :ignore
      end

      @impl Authex.Repo
      def init(config) do
        {:ok, config}
      end

      @impl Authex.Repo
      def exists?(_key) do
        :error
      end

      @impl Authex.Repo
      def insert(_key) do
        :error
      end

      @impl Authex.Repo
      def delete(_key) do
        :error
      end

      defoverridable Authex.Repo
    end
  end

  @doc false
  @spec exists?(repo :: Authex.Repo.t(), key()) :: boolean() | :error
  def exists?(repo, key) do
    do_action(repo, :exists?, key)
  end

  @doc false
  @spec insert(repo :: Authex.Repo.t(), key()) :: :ok | :error
  def insert(repo, key) do
    do_action(repo, :insert, key)
  end

  @doc false
  @spec delete(repo :: Authex.Repo.t(), key) :: :ok | :error
  def delete(repo, key) do
    do_action(repo, :delete, key)
  end

  defp do_action(repo, action, key) do
    case repo do
      false -> :error
      module -> apply(module, action, [to_string(key)])
    end
  end
end
