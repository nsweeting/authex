defmodule Authex.Verification do
  alias Authex.Config
  alias Authex.Verification

  @type t :: %__MODULE__{
    time:         integer,
    jwk:          integer,
    alg:          integer,
    blacklist:    binary,
    compact:      binary
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
    blacklist: Config.blacklist()
  ]

  @doc """
  Creates a new Authex.Verification struct from the compact token and options.

  ## Parameters

    - compact: A binary compact token.
    - options: A keyword list of options.

  ## Options
    * `:time` - the base time (timestamp format) in which to use.
    * `:secret` - the secret to verify the token with.
    * `:alg` - the algorithm to verify the token with.
    * `:blacklist` - the blacklist module to check the jti claim with.

  ## Examples

      iex> verification = Authex.Verification.new("token")
      iex> with %Authex.Verification{compact: compact} <- verification, do: compact
      "token"
  """
  @spec new(binary, list) :: Authex.Verification.t
  def new(compact, options \\ []) do
    options   = Keyword.merge(@default_opts, options)
    time      = Keyword.get(options, :time, :os.system_time(:seconds))
    secret    = Keyword.get(options, :secret)
    alg       = Keyword.get(options, :alg)
    blacklist = Keyword.get(options, :blacklist)

    %Verification{}
    |> put_time(time)
    |> put_compact(compact)
    |> put_jwk(secret)
    |> put_alg(alg)
    |> put_blacklist(blacklist)
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
end
