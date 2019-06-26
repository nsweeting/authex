defmodule Authex.Repo do
  @moduledoc """
  Defines a verification repo.

  This allows for the creation of persistent storage for blacklists. Blacklists
  are used to block usage of a token by its `:jti` key.

      defmodule MyApp.Auth.Blacklist do
        @behaviour Authex.Repo

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
  during the auth verification process. This will largely depend on the storage
  medium used.
  """

  @type t :: module() | false
  @type key :: binary() | integer()

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
