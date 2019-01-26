defmodule AuthexTest do
  use ExUnit.Case

  import Authex.TestHelpers

  alias Authex.Token

  setup_all do
    Auth.start_link()
    :ok
  end

  setup do
    reset_config()
  end

  describe "token/2" do
    test "can set the jti claim through the args or config" do
      assert %Token{jti: "foo"} = Auth.token(jti: "foo")
      save_config(default_jti: "foo")
      assert %Token{jti: "foo"} = Auth.token()
    end

    test "can set the jti claim with an mfa" do
      assert %Token{jti: "FOO"} = Auth.token(jti: {String, :upcase, ["foo"]})
    end

    test "can set the jti claim to nil with false" do
      assert %Token{jti: nil} = Auth.token(jti: false)
    end

    test "uses a uuid as the default jti claim" do
      assert %Token{jti: jti} = Auth.token()
      assert String.length(jti) == 36
    end

    test "can set the scopes claim through the args or config" do
      assert %Token{scopes: ["foo"]} = Auth.token(scopes: ["foo"])
      save_config(default_scopes: ["bar"])
      assert %Token{scopes: ["bar"]} = Auth.token()
    end

    test "can set the aud, iss and sub claim through the args or config" do
      assert %Token{aud: "foo", sub: 1, iss: "bar"} = Auth.token(aud: "foo", sub: 1, iss: "bar")
      save_config(default_aud: "foo", default_sub: 1, default_iss: "bar")
      assert %Token{aud: "foo", sub: 1, iss: "bar"} = Auth.token()
    end

    test "that arg claims overide config claims" do
      save_config(default_jti: "bar")
      assert %Token{jti: "foo"} = Auth.token(jti: "foo")
    end

    test "can set the exp through the ttl option or config" do
      assert %Token{exp: 10} = Auth.token([], ttl: 10, time: 0)
      save_config(default_ttl: 20)
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
      save_config(secret: "foo")
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
      save_config(secret: "foo")
      assert {:ok, %Token{}} = Auth.token() |> Auth.sign() |> Auth.verify()
    end

    test "returns an error tuple if the token is bad" do
      assert {:error, :bad_token} = Auth.verify("foo", secret: "foo")
    end

    test "returns an error tuple if the token was signed with another secret" do
      save_config(secret: "foo")
      token = Auth.token()
      compact_token = Auth.sign(token)
      assert {:error, :bad_token} = Auth.verify(compact_token, secret: "bar")
    end

    test "returns an error tuple if the token is expired" do
      save_config(secret: "foo")
      token = Auth.token([], ttl: -1)
      compact_token = Auth.sign(token)
      assert {:error, :expired} = Auth.verify(compact_token)
    end

    test "returns an error tuple if the token is not ready" do
      save_config(secret: "foo")
      token = Auth.token([], time: :os.system_time(:seconds) + 10)
      compact_token = Auth.sign(token)
      assert {:error, :not_ready} = Auth.verify(compact_token)
    end

    test "returns an ok tuple if the token has no nbf or exp claims" do
      save_config(secret: "foo")
      token = %{Auth.token() | nbf: nil, exp: nil}
      compact_token = Auth.sign(token)
      assert {:ok, %Token{}} = Auth.verify(compact_token)
    end

    test "returns a duplicate of the original token" do
      save_config(secret: "foo")
      token = Auth.token()
      compact_token = Auth.sign(token)
      assert Auth.verify(compact_token) == {:ok, token}
    end
  end

  describe "from_token/1" do
    test "returns a map of spec'd token attributes" do
      save_config(serializer: Serializer)
      token = Auth.token(sub: 1, scopes: ["foo"])
      assert {:ok, %{id: 1, scopes: ["foo"]}} = Auth.from_token(token)
    end

    test "will return an error if no serializer is set" do
      token = Auth.token(sub: 1, scopes: ["foo"])

      assert {:error, :no_serializer} = Auth.from_token(token)
    end
  end

  describe "from_compact_token/1" do
    test "returns a map of spec'd token attributes" do
      save_config(secret: "foo", serializer: Serializer)
      compact_token = [sub: 1, scopes: ["foo"]] |> Auth.token() |> Auth.sign()
      assert {:ok, %{id: 1, scopes: ["foo"]}} = Auth.from_compact_token(compact_token)
    end

    test "will return an error if no serializer is set" do
      save_config(secret: "foo")
      compact_token = [sub: 1, scopes: ["foo"]] |> Auth.token() |> Auth.sign()

      assert {:error, :no_serializer} = Auth.from_compact_token(compact_token)
    end
  end

  describe "for_token/1" do
    test "returns a token from a map of attributes" do
      save_config(secret: "foo", serializer: Serializer)
      assert {:ok, %Token{sub: 1, scopes: ["foo"]}} = Auth.for_token(%{id: 1, scopes: ["foo"]})
    end

    test "will return an error if no serializer is set" do
      assert {:error, :no_serializer} = Auth.for_token(%{id: 1, scopes: ["foo"]})
    end
  end

  describe "for_compact_token/1" do
    test "returns a compact token from a map of attributes" do
      save_config(secret: "foo", serializer: Serializer)
      {:ok, compact_token} = Auth.for_compact_token(%{id: 1, scopes: ["foo"]})
      assert String.length(compact_token) > 200
      assert {:ok, %{id: 1, scopes: ["foo"]}} = Auth.from_compact_token(compact_token)
    end

    test "will return an error if no serializer is set" do
      assert {:error, :no_serializer} = Auth.for_compact_token(%{id: 1, scopes: ["foo"]})
    end
  end

  describe "current_user/1" do
    test "returns the current user set in the :authex_current_user key of a Plug.Conn" do
      conn = %Plug.Conn{private: %{authex_current_user: "foo"}}
      assert {:ok, "foo"} = Auth.current_user(conn)
    end

    test "returns an error if :authex_current_user key of a Plug.Conn doesnt exist" do
      conn = %Plug.Conn{private: %{}}
      assert :error = Auth.current_user(conn)
    end

    test "returns an error if passed something that does not have a private key" do
      assert :error = Auth.current_user(%{})
    end
  end

  describe "current_scopes/1" do
    test "returns the current scopes set in the :authex_token key of a Plug.Conn" do
      conn = %Plug.Conn{private: %{authex_token: %Authex.Token{scopes: ["foo"]}}}
      assert {:ok, ["foo"]} = Auth.current_scopes(conn)
    end

    test "returns an error if :authex_current_scopes key of a Plug.Conn doesnt exist" do
      conn = %Plug.Conn{private: %{}}
      assert :error = Auth.current_scopes(conn)
    end

    test "returns an error if passed something that does not have a private key" do
      assert :error = Auth.current_scopes(%{})
    end
  end

  describe "current_token/1" do
    test "returns the current token set in the :authex_token key of a Plug.Conn" do
      token = %Authex.Token{}
      conn = %Plug.Conn{private: %{authex_token: token}}
      assert {:ok, ^token} = Auth.current_token(conn)
    end

    test "returns an error if :authex_token key of a Plug.Conn doesnt exist" do
      conn = %Plug.Conn{private: %{}}
      assert :error = Auth.current_token(conn)
    end

    test "returns an error if passed something that does not have a private key" do
      assert :error = Auth.current_token(%{})
    end
  end

  describe "blacklisted?/1" do
    test "returns false if not blacklisted" do
      save_config(blacklist: Mocklist)
      {:ok, pid} = Mocklist.start_link()
      assert Auth.blacklisted?(%Token{sub: 1}) == false
      Process.exit(pid, :kill)
    end

    test "returns true if blacklisted" do
      save_config(blacklist: Mocklist)
      {:ok, pid} = Mocklist.start_link()
      Auth.blacklist(%Token{sub: 1})
      assert Auth.blacklisted?(%Token{sub: 1}) == true
      Process.exit(pid, :kill)
    end
  end

  describe "blacklist/1" do
    test "returns ok if blacklisted" do
      save_config(blacklist: Mocklist)
      {:ok, pid} = Mocklist.start_link()
      assert Auth.blacklist(%Token{sub: 1}) == :ok
      assert Auth.blacklisted?(%Token{sub: 1}) == true
      Process.exit(pid, :kill)
    end
  end

  describe "unblacklist/1" do
    test "returns ok if unblacklisted" do
      save_config(blacklist: Mocklist)
      {:ok, pid} = Mocklist.start_link()
      assert Auth.blacklist(%Token{sub: 1}) == :ok
      assert Auth.blacklisted?(%Token{sub: 1}) == true
      assert Auth.unblacklist(%Token{sub: 1}) == :ok
      assert Auth.blacklisted?(%Token{sub: 1}) == false
      Process.exit(pid, :kill)
    end
  end

  describe "init/1" do
    test "can be used to overide the default config" do
      AuthTwo.start_link(secret: "foo")
      assert AuthTwo.config(:secret) == "bar"
    end
  end
end
