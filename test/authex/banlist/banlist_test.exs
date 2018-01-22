defmodule Authex.BanlistTest do
  use ExUnit.Case

  alias Authex.Banlist
  alias Authex.Banlist.Basic

  setup do
    Basic.start_link()
    :ok
  end

  test "get/2 uses the banlist that is passed to it" do
    assert Banlist.get(Basic, "test") == false
  end

  test "set/2 uses the banlist that is passed to it" do
    assert Banlist.set(Basic, "test") == :ok
    assert Banlist.get(Basic, "test") == true
  end

  test "del/2 uses the banlist that is passed to it" do
    assert Banlist.set(Basic, "test") == :ok
    assert Banlist.get(Basic, "test") == true
    assert Banlist.del(Basic, "test") == :ok
    assert Banlist.get(Basic, "test") == false
  end
end
