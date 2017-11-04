defmodule Authex.Checker.Default do
  use Authex.Checker

  alias Authex.Blacklist
  alias Authex.Token
  alias Authex.Verification

  @spec handle_run(Authex.Verification.t) :: {:ok, Authex.Token.t} | {:error, atom}
  def handle_run(%Verification{jwk: jwk, alg: alg, time: time, blacklist: blacklist, compact: compact}) do
    with {:ok, claims} <- check_token(jwk, alg, compact),
         token <- Token.from_map(claims),
         :ok <- check_nbf(time, token.nbf),
         :ok <- check_exp(time, token.exp),
         :ok <- check_blacklist(blacklist, token.jti)
    do
      {:ok, token}
    else
      error -> error
    end
  end

  defp check_token(jwk, alg, compact) do
    case JOSE.JWT.verify_strict(jwk, alg, compact) do
      {true, %{fields: claims}, _} -> {:ok, claims}
      {false, _, _} -> {:error, :bad_token}
      {:error, _} -> {:error, :bad_token}
    end
  end

  defp check_nbf(time, nbf) when is_integer(nbf) and time > nbf do
    :ok
  end
  defp check_nbf(_, _) do
    {:error, :not_ready}
  end

  defp check_exp(time, exp) when is_integer(exp) and time < exp do
    :ok
  end
  defp check_exp(_, _) do
    {:error, :expired}
  end

  defp check_blacklist(false, _) do
    :ok
  end
  defp check_blacklist(blacklist, jti)
  when is_atom(blacklist) and is_binary(jti) do
    case Blacklist.get(blacklist, jti) do
      false  -> :ok
      true   -> {:error, :blacklisted}
      :error -> {:error, :blacklist_error}      
    end
  end
  defp check_blacklist(_, _) do
    {:error, :jti_unverified}
  end
end
