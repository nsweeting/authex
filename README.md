# Authex

[![Build Status](https://travis-ci.org/nsweeting/authex.svg?branch=master)](https://travis-ci.org/nsweeting/authex)
[![Authex Version](https://img.shields.io/hexpm/v/authex.svg)](https://hex.pm/packages/authex)

Authex is a simple JWT authentication and authorization library for Elixir.

## Installation

The package can be installed by adding `authex` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:authex, "~> 0.1.0"}
  ]
end
```

## Documentation

See [HexDocs](https://hexdocs.pm/authex) for additional documentation.

## Getting Started

Before starting, we should configure Authex. At a minimum, we need to add a secret
from which our tokens will be signed with. There is a convenient mix task available
for this.

```
mix authex.gen.secret
```

We should now add this secret to our config. In production this should be set via
an env var. By default, authex will pick up the env var `AUTH_SECRET` if we have
not set one via config.

```elixir
config :authex, [
  # REQUIRED
  # The secret used to sign tokens with.
  secret: "mysecret",

  # OPTIONAL
  # A blacklist module, or false if disabled.
  blacklist: false,
  # The default serializer module.
  serializer: Authex.Serializer.Basic,
  # The default algorithm used to sign tokens.
  default_alg: :hs256,
  # The default iss claim used in tokens.
  default_iss: nil,
  # The default aud claim used in tokens.
  default_aud: nil,
  # The default time to live for tokens in seconds.
  default_ttl: 3600,
  # The default module, function, and arg used to generate the jti claim.
  jti_mfa: {UUID, :uuid4, [:hex]}
]
```

The above config is all the defaults "out of the box".

## Usage by Example

Create a token using the default serializer. This assumes users have an `id` field.

```elixir
MyApp.User
|> MyApp.Repo.get(1)
|> Authex.for_token()
```

Create a token with the sub and iss claim set. The token will also have a time
to live of 60 seconds. `Authex.token/1` returns an `Authex.Token` struct. `Authex.sign/1`
creates a compact token from an `Authex.Token` struct.

```elixir
user = MyApp.Repo.get(MyApp.User, 1)
token = Authex.token([sub: user.id, iss: "myapp"], [ttl: 60])
Authex.sign(token)
```

Verify a compact token and return an `Authex.Token` struct.

```elixir
MyApp.User
|> MyApp.Repo.get(1)
|> Authex.for_token()
|> Authex.verify()
```

Verify a compact token and return a resource created from a serializer.

```elixir
MyApp.User
|> MyApp.Repo.get(1)
|> Authex.for_token()
|> Authex.from_token()
```

Create a custom Serializer.

```elixir
defmodule MyApp.TokenSerializer do
  use Authex.Serializer

  def from_token(%Authex.Token{sub: sub, scopes: scopes}) do
    %MyApp.User{id: sub, scopes: scopes}
  end

  def for_token(%MyApp.User{id: id, scopes: scopes}) do
    Authex.Token.new([sub: id, scopes: scopes])
  end
end

```

Authenticate a Phoenix controller using a custom serializer. `Authex.Plug.Authenticate`
looks for the `Authenicate: Bearer mytoken` header. It will then verify,
and deserialize the token using the provided serializer.

If any of these steps fails, it will put a 401 status and halt the conn.

Otherwise, the plug will place the value returned from the serializer into the conn.
You can access this value again using `Authex.current_user/1`.

```elixir
defmodule MyApp.Web.UserController do
  use MyApp.Web, :controller

  plug :authenticate

  def show(conn, _params) do
    with {:ok, %{id: id}} <- Authex.current_user(conn),
         {:ok, user} <- MyApp.Users.get(id)
    do
      render(conn, "show.json", user: user)
    end
  end

  defp authenticate(conn, _opts) do
    opts = Authex.Plug.Authentication.init([serializer: MyApp.TokenSerializer])
    Authex.Plug.Authentication.call(conn, opts)
  end
end
```

Authorize a user to access a particular endpoint using their token scopes.

Authorization works by combining the "permits" with the "type" of request that
is being made.

For example, with our controller below, we are permitting "user" and "admin"
access. The show action would be a `GET` request, and would therefore be a "read"
type.

So, in order to access the show action, our token would require one of the
two following scopes: `["user/read", "admin/read"].

Requests are bucketed under the following types:

  * "GET" - "read"
  * "HEAD" - "read"
  * "PUT" - "write"
  * "PATCH" - "write"
  * "POST" - "write"
  * "DELETE" - "delete"

```elixir
defmodule MyApp.Web.UserController do
  use MyApp.Web, :controller

  plug :authenticate
  plug :authorize, permits: ["user", "admin"]

  def show(conn, _params) do
    with {:ok, %{id: id}} <- Authex.current_user(conn),
         {:ok, user} <- MyApp.Users.get(id)
    do
      render(conn, "show.json", user: user)
    end
  end

  defp authenticate(conn, _opts) do
    opts = Authex.Plug.Authentication.init([serializer: MyApp.TokenSerializer])
    Authex.Plug.Authentication.call(conn, opts)
  end

  defp authorize(conn, opts) do
    opts = Authex.Plug.Authorization.init(opts)
    Authex.Plug.Authorization.call(conn, opts)
  end
end
```