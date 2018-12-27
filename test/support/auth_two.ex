defmodule AuthTwo do
  use Authex, otp_app: :authex

  def init(config) do
    config = Keyword.put(config, :secret, "bar")
    {:ok, config}
  end
end
