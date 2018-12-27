# lifed from Phoenix gen secret
# https://raw.githubusercontent.com/phoenixframework/phoenix/master/lib/mix/tasks/phx.gen.secret.ex
defmodule Mix.Tasks.Authex.Gen.Secret do
  @shortdoc "Generates a secret"

  @moduledoc """
  Generates a secret and prints it to the terminal.

      mix authex.gen.secret [length]

  By default, mix authex.gen.secret generates a key 64 characters long.
  The minimum value for `length` is 32.
  """
  use Mix.Task

  @doc false
  def run(opts \\ [])

  def run([]), do: run(["64"])

  def run([int]) do
    int
    |> parse!()
    |> generate()
    |> Mix.Shell.IO.info()
  end

  def run([_ | _]), do: invalid_args!()

  defp parse!(int) do
    case Integer.parse(int) do
      {int, ""} -> int
      _ -> invalid_args!()
    end
  end

  defp generate(length) when length > 31 do
    case Authex.Secret.new(length) do
      :error -> Mix.raise("The secret could not be generated")
      {:ok, secret} -> secret
    end
  end

  defp generate(_), do: Mix.raise("The secret should be at least 32 characters long")

  @spec invalid_args!() :: no_return()
  defp invalid_args! do
    Mix.raise("mix authex.gen.secret expects a length as integer or no argument at all")
  end
end
