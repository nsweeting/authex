defmodule Authex.Secret do
  def new(length \\ 64)
  def new(length) when is_integer(length) and length > 31 do
    secret = length
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
    |> binary_part(0, length)

    {:ok, secret}
  end
  def new(_) do
    :error
  end
end
