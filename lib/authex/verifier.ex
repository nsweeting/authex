defmodule Authex.Verifier do
  alias Authex.Config
  alias Authex.Token
  alias Authex.Verifier

  defstruct [
    :time, 
    :jwk,
    :alg,
    :blacklist,
    :compact
  ]

  def new(compact, options \\ []) do
    time      = Keyword.get(options, :time, :os.system_time(:seconds))
    secret    = Keyword.get(options, :secret, Config.secret())
    alg       = Keyword.get(options, :alg, :hs256)
    blacklist = Keyword.get(options, :blacklist, Authex.Blacklist)

    %Verifier{}
    |> put_time(time)
    |> put_compact(compact)
    |> put_jwk(secret)
    |> put_alg(alg)
    |> put_blacklist(blacklist)
  end

  def run(%Verifier{jwk: jwk, alg: alg, time: time, blacklist: blacklist, compact: compact}) do
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

  def put_time(verifier, time) do
    %{verifier | time: time}
  end

  def put_compact(verifier, compact) do
    %{verifier | compact: compact}
  end

  def put_jwk(verifier, secret) do
    jwk = %{"kty" => "oct", "k" => secret}
    %{verifier | jwk: jwk}
  end

  def put_alg(verifier, :hs256) do
    %{verifier | alg: ["HS256"]}
  end
  def put_alg(verifier, :hs384) do
    %{verifier | alg: ["HS384"]}
  end
  def put_alg(verifier, :hs512) do
    %{verifier | alg: ["HS512"]}
  end
  def put_alg(verifier, _) do
    %{verifier | alg: []}
  end

  def put_blacklist(verifier, blacklist) do
    %{verifier | blacklist: blacklist}
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

  # WIP
  defp check_blacklist(_, _) do
    :ok
  end
end
