defmodule AuthexTest do
  use ExUnit.Case

  import Authex.TestHelpers

  alias Auth.Test, as: Auth
  alias Authex.Token

  setup do
    reset_config()
  end

  describe "token/2" do
    test "can set the jti claim through the args or config" do
      assert %Token{jti: "foo"} = Auth.token(jti: "foo")
      set_config(default_jti: "foo")
      assert %Token{jti: "foo"} = Auth.token()
    end

    test "can set the jti claim with an mfa" do
      assert %Token{jti: "FOO"} = Auth.token(jti: {String, :upcase, ["foo"]})
    end

    test "can set the jti claim to nil with false" do
      assert %Token{jti: nil} = Auth.token(jti: false)
    end

    test "uses a uuid hex as the default jti claim" do
      assert %Token{jti: jti} = Auth.token()
      assert String.length(jti) == 32
    end

    test "can set the scopes claim through the args or config" do
      assert %Token{scopes: ["foo"]} = Auth.token(scopes: ["foo"])
      set_config(default_scopes: ["bar"])
      assert %Token{scopes: ["bar"]} = Auth.token()
    end

    test "can set the aud, iss and sub claim through the args or config" do
      assert %Token{aud: "foo", sub: 1, iss: "bar"} = Auth.token(aud: "foo", sub: 1, iss: "bar")
      set_config(default_aud: "foo", default_sub: 1, default_iss: "bar")
      assert %Token{aud: "foo", sub: 1, iss: "bar"} = Auth.token()
    end

    test "that arg claims overide config claims" do
      set_config(default_jti: "bar")
      assert %Token{jti: "foo"} = Auth.token(jti: "foo")
    end

    test "can set the exp through the ttl option or config" do
      assert %Token{exp: 10} = Auth.token([], ttl: 10, time: 0)
      set_config(default_ttl: 20)
      assert %Token{exp: 20} = Auth.token([], time: 0)
    end

    test "uses 3600 seconds as the default ttl" do
      assert %Token{exp: 3600} = Auth.token([], time: 0)
    end
  end

  describe "sign/2" do
    test "returns a compact token" do
      compact_token = Auth.token() |> Auth.sign(secret: "foo")
      assert String.length(compact_token) > 200
    end

    test "can set the secret from the options or config" do
      compact_token1 = Auth.token([jti: "foo"], time: 0) |> Auth.sign(secret: "foo")
      set_config(secret: "foo")
      compact_token2 = Auth.token([jti: "foo"], time: 0) |> Auth.sign()
      assert compact_token1 == compact_token2
    end

    test "will raise if no secret is set" do
      assert_raise Authex.Error, "secret cannot be nil", fn ->
        Auth.token() |> Auth.sign()
      end
    end
  end

  describe "verify/2" do
    test "returns an ok token tuple if valid" do
      set_config(secret: "foo")
      assert {:ok, %Token{}} = Auth.token() |> Auth.sign() |> Auth.verify()
    end

    test "returns an error tuple if the token is bad" do
      assert {:error, :bad_token} = Auth.verify("foo", secret: "foo")
    end

    test "returns an error tuple if the token was signed with another secret" do
      set_config(secret: "foo")
      token = Auth.token()
      compact_token = Auth.sign(token)
      assert {:error, :bad_token} = Auth.verify(compact_token, secret: "bar")
    end

    test "returns an error tuple if the token is expired" do
      set_config(secret: "foo")
      token = Auth.token([], ttl: -1)
      compact_token = Auth.sign(token)
      assert {:error, :expired} = Auth.verify(compact_token)
    end

    test "returns an error tuple if the token is not ready" do
      set_config(secret: "foo")
      token = Auth.token([], time: :os.system_time(:seconds) + 10)
      compact_token = Auth.sign(token)
      assert {:error, :not_ready} = Auth.verify(compact_token)
    end

    test "returns a duplicate of the original token" do
      set_config(secret: "foo")
      token = Auth.token()
      compact_token = Auth.sign(token)
      assert Auth.verify(compact_token) == {:ok, token}
    end
  end

  describe "from_token/1" do
    test "returns a map of spec'd token attributes" do
      set_config(serializer: Serializer.Test)
      token = Auth.token(sub: 1, scopes: ["foo"])
      assert %{id: 1, scopes: ["foo"]} = Auth.from_token(token)
    end

    test "will raise an error if no serializer is set" do
      token = Auth.token(sub: 1, scopes: ["foo"])
      assert_raise Authex.Error, "no serializer configured", fn ->
        Auth.from_token(token)
      end
    end
  end

  describe "from_compact_token/1" do
    test "returns a map of spec'd token attributes" do
      set_config(secret: "foo", serializer: Serializer.Test)
      compact_token = [sub: 1, scopes: ["foo"]] |> Auth.token() |> Auth.sign()
      assert %{id: 1, scopes: ["foo"]} = Auth.from_compact_token(compact_token)
    end

    test "will raise an error if no serializer is set" do
      set_config(secret: "foo")
      compact_token = [sub: 1, scopes: ["foo"]] |> Auth.token() |> Auth.sign()
      assert_raise Authex.Error, "no serializer configured", fn ->
        Auth.from_compact_token(compact_token)
      end
    end
  end

  describe "for_token/1" do
    test "returns a token from a map of attributes" do
      set_config(secret: "foo", serializer: Serializer.Test)
      assert %Token{sub: 1, scopes: ["foo"]} = Auth.for_token(%{id: 1, scopes: ["foo"]})
    end

    test "will raise an error if no serializer is set" do
      assert_raise Authex.Error, "no serializer configured", fn ->
        Auth.for_token(%{id: 1, scopes: ["foo"]})
      end
    end
  end

  describe "for_compact_token/1" do
    test "returns a compact token from a map of attributes" do
      set_config(secret: "foo", serializer: Serializer.Test)
      compact_token = Auth.for_compact_token(%{id: 1, scopes: ["foo"]})
      assert String.length(compact_token) > 200
      assert %{id: 1, scopes: ["foo"]} = Auth.from_compact_token(compact_token)
    end

    test "will raise an error if no serializer is set" do
      assert_raise Authex.Error, "no serializer configured", fn ->
        Auth.for_compact_token(%{id: 1, scopes: ["foo"]})
      end
    end
  end

  describe "banned?/1" do
    test "returns false if not banned" do
      set_config(banlist: Banlist.Test)
      {:ok, pid} = Banlist.Test.start_link()
      assert Auth.banned?(1) == false
      Process.exit(pid, :kill)
    end

    test "returns true if banned" do
      set_config(banlist: Banlist.Test)
      {:ok, pid} = Banlist.Test.start_link()
      Auth.ban(1)
      assert Auth.banned?(1) == true
      Process.exit(pid, :kill)
    end
  end

  describe "ban/1" do
    test "returns ok if banned" do
      set_config(banlist: Banlist.Test)
      {:ok, pid} = Banlist.Test.start_link()
      assert Auth.ban(1) == :ok
      assert Auth.banned?(1) == true
      Process.exit(pid, :kill)
    end
  end

  describe "unban/1" do
    test "returns ok if unbanned" do
      set_config(banlist: Banlist.Test)
      {:ok, pid} = Banlist.Test.start_link()
      assert Auth.ban(1) == :ok
      assert Auth.banned?(1) == true
      assert Auth.unban(1) == :ok
      assert Auth.banned?(1) == false
      Process.exit(pid, :kill)
    end
  end

  describe "blacklisted?/1" do
    test "returns false if not blacklisted" do
      set_config(blacklist: Blacklist.Test)
      {:ok, pid} = Blacklist.Test.start_link()
      assert Auth.blacklisted?(1) == false
      Process.exit(pid, :kill)
    end

    test "returns true if blacklisted" do
      set_config(blacklist: Blacklist.Test)
      {:ok, pid} = Blacklist.Test.start_link()
      Auth.blacklist(1)
      assert Auth.blacklisted?(1) == true
      Process.exit(pid, :kill)
    end
  end

  describe "blacklist/1" do
    test "returns ok if blacklisted" do
      set_config(blacklist: Blacklist.Test)
      {:ok, pid} = Blacklist.Test.start_link()
      assert Auth.blacklist(1) == :ok
      assert Auth.blacklisted?(1) == true
      Process.exit(pid, :kill)
    end
  end

  describe "unblacklist/1" do
    test "returns ok if unblacklisted" do
      set_config(blacklist: Blacklist.Test)
      {:ok, pid} = Blacklist.Test.start_link()
      assert Auth.blacklist(1) == :ok
      assert Auth.blacklisted?(1) == true
      assert Auth.unblacklist(1) == :ok
      assert Auth.blacklisted?(1) == false
      Process.exit(pid, :kill)
    end
  end

  describe "set_secret/1" do
    test "sets the secret key config" do
      assert Auth.config(:secret) == nil
      Auth.set_secret("foo")
      assert Auth.config(:secret) == "foo"
    end
  end
end
