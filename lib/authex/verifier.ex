defmodule Authex.Verifier do
  alias Authex.Blacklist
  alias Authex.Config
  alias Authex.Token
  alias Authex.Verifier

  @type t :: %__MODULE__{
    time:         integer,
    jwk:          integer,
    alg:          integer,
    blacklist:    binary,
    compact:      binary,
  }

  defstruct [
    :time, 
    :jwk,
    :alg,
    :blacklist,
    :compact
  ]

  @default_opts [
    alg:       Config.default_alg(),
    secret:    Config.secret(),
    blacklist: Config.blacklist(),
  ]

  @doc """
  Creates a new Authex.Verifier struct from the compact token and options.

  ## Parameters

    - compact: A binary compact token.
    - options: A keyword list of options.

  ## Options
    * `:time` - the base time (timestamp format) in which to use.
    * `:secret` - the secret to verify the token with..
    * `:alg` - the algorithm to verify the token with.
    * `:blacklist` - the blacklist module to check the jti claim with.

  ## Examples

      iex> verifier = Authex.Verifier.new("token")
      iex> with %Authex.Verifier{compact: compact} <- verifier, do: compact
      "token"
  """
  def new(compact, options \\ []) do
    options   = Keyword.merge(@default_opts, options)
    time      = Keyword.get(options, :time, :os.system_time(:seconds))
    secret    = Keyword.get(options, :secret)
    alg       = Keyword.get(options, :alg)
    blacklist = Keyword.get(options, :blacklist)

    %Verifier{}
    |> put_time(time)
    |> put_compact(compact)
    |> put_jwk(secret)
    |> put_alg(alg)
    |> put_blacklist(blacklist)
  end

  @doc """
  Runs an Authex.Verifier struct - checking that the token is valid.

  ## Parameters

    - verifier: An Authex.Verifier struct.

  ## Examples

      iex> {:ok, token} = [sub: 1]
      ...> |> Authex.token()
      ...> |> Authex.sign()
      ...> |> Authex.Verifier.new()
      ...> |> Authex.Verifier.run()
      iex> with %Authex.Token{sub: sub} <- token, do: sub
      1
  """
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

  @doc false
  def put_time(verifier, time) do
    %{verifier | time: time}
  end

  @doc false
  def put_compact(verifier, compact) do
    %{verifier | compact: compact}
  end

  @doc false
  def put_jwk(verifier, secret) do
    jwk = %{"kty" => "oct", "k" => secret}
    %{verifier | jwk: jwk}
  end

  @doc false
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

  @doc false
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
