defmodule Authex.BlacklistTest do
  use ExUnit.Case
  #doctest Authex.Serializer

  alias Authex.Blacklist
  alias Authex.Blacklist.Basic

  setup do
    Basic.start_link()
    :ok
  end

  test "get/2 uses the blacklist that is passed to it" do
    assert Blacklist.get(Basic, "test") == false
  end

  test "set/2 uses the blacklist that is passed to it" do
    assert Blacklist.set(Basic, "test") == :ok
    assert Blacklist.get(Basic, "test") == true
  end

  test "del/2 uses the blacklist that is passed to it" do
    assert Blacklist.set(Basic, "test") == :ok
    assert Blacklist.get(Basic, "test") == true
    assert Blacklist.del(Basic, "test") == :ok
    assert Blacklist.get(Basic, "test") == false
  end
end
