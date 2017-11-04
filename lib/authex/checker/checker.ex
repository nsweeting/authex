defmodule Authex.Checker do
  alias Authex.Checker
  alias Authex.Config
  alias Authex.Verification

  @callback handle_run(Authex.Verification.t) :: term | :error

  defmacro __using__(_) do
    quote location: :keep do
      @behaviour Checker 

      def handle_run(_) do
        {:error, :not_implemented}
      end

      defoverridable Checker
    end
  end

  @doc """
  Runs an Authex.Verification struct through the default checker module.

  ## Parameters

    - verification: An Authex.Verification struct.

  ## Examples

      iex> {:ok, token} = [sub: 1]
      ...> |> Authex.token()
      ...> |> Authex.sign()
      ...> |> Authex.Verification.new()
      ...> |> Authex.Checker.run()
      iex> with %Authex.Token{sub: sub} <- token, do: sub
      1
  """
  @spec run(Authex.Verification.t) :: {:ok, Authex.Token.t} | {:error, atom}
  def run(verification) do
    Config.checker() |> run(verification)
  end

  @doc """
  Runs an Authex.Verification struct through the specified checker module.

  ## Parameters

    - checker: A checker module.
    - verification: An Authex.Verification struct.
  """
  @spec run(atom, Authex.Verification.t) :: {:ok, Authex.Token.t} | {:error, atom}
  def run(checker, %Verification{} = verification) do
    apply(checker, :handle_run, [verification])
  end
end
