defmodule AuthexTest do
  use ExUnit.Case

  alias Authex.Token

  describe "token/2" do
    test "can set the jti claim through the args or config" do
      start_supervised(Auth, id: :one)
      assert %Token{jti: "foo"} = Authex.token(Auth, jti: "foo")
      start_supervised({Auth, [default_jti: "bar"]}, id: :two)
      assert %Token{jti: "bar"} = Authex.token(Auth)
    end

    test "can set the jti claim with an mfa" do
      start_supervised(Auth)
      assert %Token{jti: "FOO"} = Authex.token(Auth, jti: {String, :upcase, ["foo"]})
    end

    test "can set the jti claim to nil with false" do
      start_supervised(Auth)
      assert %Token{jti: nil} = Authex.token(Auth, jti: false)
    end

    test "uses a uuid as the default jti claim" do
      start_supervised(Auth)
      assert %Token{jti: jti} = Authex.token(Auth)
      assert String.length(jti) == 36
    end

    test "can set the scopes claim through the args or config" do
      start_supervised(Auth, id: :one)
      assert %Token{scopes: ["foo"]} = Authex.token(Auth, scopes: ["foo"])
      start_supervised({Auth, [default_scopes: ["bar"]]}, id: :two)
      assert %Token{scopes: ["bar"]} = Authex.token(Auth)
    end

    test "can set the aud, iss and sub claim through the args or config" do
      start_supervised(Auth, id: :one)

      assert %Token{aud: "foo", sub: 1, iss: "bar"} =
               Authex.token(Auth, aud: "foo", sub: 1, iss: "bar")

      start_supervised({Auth, [default_aud: "bar", default_sub: 2, default_iss: "foo"]}, id: :two)

      assert %Token{aud: "bar", sub: 2, iss: "foo"} = Authex.token(Auth)
    end

    test "that arg claims overide config claims" do
      start_supervised({Auth, default_jti: "foo"})
      assert %Token{jti: "foo"} = Authex.token(Auth)
      assert %Token{jti: "bar"} = Authex.token(Auth, jti: "bar")
    end

    test "can set the exp through the ttl option or config" do
      start_supervised(Auth, id: :one)
      assert %Token{exp: 10} = Authex.token(Auth, [], ttl: 10, time: 0)
      start_supervised({Auth, [default_ttl: 20]}, id: :two)
      assert %Token{exp: 20} = Authex.token(Auth, [], time: 0)
    end

    test "can set an infinity exp through the ttl option" do
      start_supervised(Auth, id: :one)
      assert %Token{exp: nil} = Authex.token(Auth, [], ttl: :infinity)
    end

    test "uses 3600 seconds as the default ttl" do
      start_supervised(Auth)
      assert %Token{exp: 3600} = Authex.token(Auth, [], time: 0)
    end
  end

  describe "sign/2" do
    test "returns a compact token" do
      start_supervised(Auth)
      token = Authex.token(Auth)
      compact_token = Authex.sign(Auth, token, secret: "foo")
      assert String.length(compact_token) > 200
    end

    test "can set the secret from the options or config" do
      start_supervised(Auth, id: :one)
      compact_token1 = Authex.compact_token(Auth, [jti: "foo"], time: 0, secret: "bar")
      start_supervised({Auth, [secret: "bar"]}, id: :two)
      compact_token2 = Authex.compact_token(Auth, [jti: "foo"], time: 0)
      assert compact_token1 == compact_token2
    end
  end

  describe "verify/2" do
    test "returns an ok token tuple if valid" do
      start_supervised(Auth)
      compact_token = Authex.compact_token(Auth)
      assert {:ok, %Token{}} = Authex.verify(Auth, compact_token)
    end

    test "returns an error tuple if the token is bad" do
      start_supervised(Auth)
      assert {:error, :bad_token} = Authex.verify(Auth, "foo", secret: "foo")
    end

    test "returns an error tuple if the token was signed with another secret" do
      start_supervised(Auth)
      compact_token = Authex.compact_token(Auth)
      assert {:error, :bad_token} = Authex.verify(Auth, compact_token, secret: "bar")
    end

    test "returns an error tuple if the token is expired" do
      start_supervised(Auth)
      compact_token = Authex.compact_token(Auth, [], ttl: -1)
      assert {:error, :expired} = Authex.verify(Auth, compact_token)
    end

    test "returns an error tuple if the token is not ready" do
      start_supervised(Auth)
      compact_token = Authex.compact_token(Auth, [], time: :os.system_time(:seconds) + 10)
      assert {:error, :not_ready} = Authex.verify(Auth, compact_token)
    end

    test "returns an ok tuple if the token has no nbf or exp claims" do
      start_supervised(Auth)
      token = %{Authex.token(Auth) | nbf: nil, exp: nil}
      compact_token = Authex.sign(Auth, token)
      assert {:ok, %Token{}} = Authex.verify(Auth, compact_token)
    end

    test "returns a duplicate of the original token" do
      start_supervised(Auth)
      token = Authex.token(Auth)
      compact_token = Authex.sign(Auth, token)
      assert {:ok, token} = Authex.verify(Auth, compact_token)
    end
  end

  describe "refresh/3" do
    test "returns a new valid token" do
      start_supervised(Auth)
      claims = [sub: "foo", iss: "foo", scopes: ["foo"], meta: %{foo: "foo"}]
      token = Authex.token(Auth, claims, time: System.system_time(:second) - 1)
      new_token = Authex.refresh(Auth, token)

      assert token.sub == new_token.sub
      assert token.iss == new_token.iss
      assert token.scopes == new_token.scopes
      assert token.meta == new_token.meta
      assert token.jti != new_token.jti
      assert token.exp != new_token.exp
      assert token.nbf != new_token.nbf
      assert token.iat != new_token.iat
    end
  end

  describe "from_token/1" do
    test "returns a map of spec'd token attributes" do
      start_supervised(Auth)
      token = Authex.token(Auth, sub: 1, scopes: ["foo"])
      assert {:ok, %{id: 1, scopes: ["foo"]}} = Authex.from_token(Auth, token)
    end
  end

  describe "for_token/1" do
    test "returns a token from a map of attributes" do
      start_supervised(Auth)
      assert {:ok, token} = Authex.for_token(Auth, %{id: 1, scopes: ["foo"]})
      compact_token = Authex.sign(Auth, token)
      assert {:ok, %Token{sub: 1, scopes: ["foo"]}} = Authex.verify(Auth, compact_token)
    end
  end

  describe "current_resource/1" do
    test "returns the current resource set in the :authex_resource key of a Plug.Conn" do
      conn = %Plug.Conn{private: %{authex_resource: "foo"}}
      assert {:ok, "foo"} = Authex.current_resource(conn)
    end

    test "returns an error if :authex_resource key of a Plug.Conn doesnt exist" do
      conn = %Plug.Conn{private: %{}}
      assert :error = Authex.current_resource(conn)
    end

    test "returns an error if passed something that does not have a private key" do
      assert :error = Authex.current_resource(%{})
    end
  end

  describe "current_scopes/1" do
    test "returns the current scopes set in the :authex_token key of a Plug.Conn" do
      conn = %Plug.Conn{private: %{authex_token: %Authex.Token{scopes: ["foo"]}}}
      assert {:ok, ["foo"]} = Authex.current_scopes(conn)
    end

    test "returns an error if :authex_current_scopes key of a Plug.Conn doesnt exist" do
      conn = %Plug.Conn{private: %{}}
      assert :error = Authex.current_scopes(conn)
    end

    test "returns an error if passed something that does not have a private key" do
      assert :error = Authex.current_scopes(%{})
    end
  end

  describe "current_token/1" do
    test "returns the current token set in the :authex_token key of a Plug.Conn" do
      token = %Authex.Token{}
      conn = %Plug.Conn{private: %{authex_token: token}}
      assert {:ok, ^token} = Authex.current_token(conn)
    end

    test "returns an error if :authex_token key of a Plug.Conn doesnt exist" do
      conn = %Plug.Conn{private: %{}}
      assert :error = Authex.current_token(conn)
    end

    test "returns an error if passed something that does not have a private key" do
      assert :error = Authex.current_token(%{})
    end
  end

  describe "blacklisted?/1" do
    test "returns false if not blacklisted" do
      start_supervised({Auth, [blacklist: Mocklist]})
      start_supervised(Mocklist)

      assert Authex.blacklisted?(Auth, %Token{sub: 1}) == false
    end

    test "returns true if blacklisted" do
      start_supervised({Auth, [blacklist: Mocklist]})
      start_supervised(Mocklist)

      Authex.blacklist(Auth, %Token{sub: 1})

      assert Authex.blacklisted?(Auth, %Token{sub: 1}) == true
    end
  end

  describe "blacklist/1" do
    test "returns ok if blacklisted" do
      start_supervised({Auth, [blacklist: Mocklist]})
      start_supervised(Mocklist)

      assert Authex.blacklist(Auth, %Token{sub: 1}) == :ok
      assert Authex.blacklisted?(Auth, %Token{sub: 1}) == true
    end
  end

  describe "unblacklist/1" do
    test "returns ok if unblacklisted" do
      start_supervised({Auth, [blacklist: Mocklist]})
      start_supervised(Mocklist)

      assert Authex.blacklist(Auth, %Token{sub: 1}) == :ok
      assert Authex.blacklisted?(Auth, %Token{sub: 1}) == true
      assert Authex.unblacklist(Auth, %Token{sub: 1}) == :ok
      assert Authex.blacklisted?(Auth, %Token{sub: 1}) == false
    end
  end
end
