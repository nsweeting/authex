defmodule Authex.Secret do
  @moduledoc false

  @spec new(integer) :: binary | :error
  def new(length \\ 64)

  def new(length) when is_integer(length) and length > 31 do
    secret =
      length
      |> :crypto.strong_rand_bytes()
      |> Base.url_encode64(padding: false)
      |> binary_part(0, length)

    {:ok, secret}
  rescue
    _ -> :error
  end

  def new(_) do
    :error
  end
end
