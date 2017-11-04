# Authex

[![Build Status](https://travis-ci.org/nsweeting/authex.svg?branch=master)](https://travis-ci.org/nsweeting/authex)
[![Authex Version](https://img.shields.io/hexpm/v/authex.svg)](https://hex.pm/packages/authex)

Authex is a simple JWT authentication and authorization library for Elixir.

## Installation

The package can be installed by adding `authex` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:authex, "~> 0.1.2"}
  ]
end
```

## Documentation

See [HexDocs](https://hexdocs.pm/authex) for additional documentation.

## Configuration

Before starting, we should configure Authex. At a minimum, we need to add a secret from which our tokens will be signed with. There is a convenient mix task available for this.

```
mix authex.gen.secret
```

We should now add this secret to our config. In production this should be set via an env var. By default, authex will pick up the env var `AUTH_SECRET` if we have not set one via config.

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

## Creating Tokens

At the heart of token creation is the `Authex.Token` struct. This struct is simply a wrapper around the typical JWT claims. The only additional item is the `:scopes` key.

We can easily create `Authex.Token` structs using the `Authex.token/2` function.

```elixir
Authex.token([sub: 1, scopes: ["admin/read"])
```

The above would create an `Authex.Token` struct for a user with an id of 1, and with "admin/read" authorization.

## Signing Tokens

Once we have a `Authex.Token` struct, we can sign it to create a compact token binary. This is what we will use for authentication and authorization for our API.

```elixir
[sub: 1, scopes: ["admin/read"]]
|> Authex.token()
|> Authex.sign()
```

## Verifying Tokens

Once we have compact token binary, we can verify it and turn it back to an `Authex.Token` struct.

```elixir
[sub: 1, scopes: ["admin/read"]]
|> Authex.token()
|> Authex.sign()
|> Authex.verify()
```


## Creating Tokens with Serializers

Typically, we want to be able to create tokens from another source of data. This could be something like a `User` struct. We also will want to take a token and turn it back into a `User` struct.

To do this, we will create a serializer. A serializer is simply a module that adopts the `Authex.Serializer` behaviour.

```elixir
defmodule MyApp.TokenSerializer do
  use Authex.Serializer

  def handle_from_token(%Authex.Token{sub: sub, scopes: scopes}) do
    %MyApp.User{id: sub, scopes: scopes}
  end

  def handle_for_token(%MyApp.User{id: id, scopes: scopes}) do
    Authex.Token.new([sub: id, scopes: scopes])
  end
end
```

We will then want to define our serializer in our config.

```elixir
config :authex, [
  serializer: MyApp.TokenSerializer,
]
```

We can now easily create compact tokens from our `User` structs using the `Authex.for_token/1` function.

```elixir
user = %MyApp.User{id: 1, scopes: []}
Authex.for_token(user)
```

We can also turn compact tokens back into our `User` structs using the `Authex.from_token/1` function.

```elixir
user = %MyApp.User{id: 1, scopes: []}
compact_token = Authex.for_token(user)
Authex.from_token(compact_token)
```

## Authenticating Endpoints

We can authenticate a Phoenix controller using the `Authex.Plug.Authentication` plug. This plug looks for the `Authenicate: Bearer mytoken` header. It will then verify, and deserialize the token using our configured serializer.

We can access our current user from the conn using the `Authex.current_user/1` function.

By default, if authentication fails, the plug sends the conn to the `Authex.Plug.Unauthorized` plug. This plug will put a `401` status into the conn with the body `"Unauthorized"`. We can configure our own unauthorized plug by passing it as an option to the `Authex.Plug.Authentication` plug.

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

  # Authenticates the user, and sends them to our custom plug if it fails.
  defp authenticate(conn, _opts) do
    opts = Authex.Plug.Authentication.init([unauthorized: MyApp.UnauthorizedPlug])
    Authex.Plug.Authentication.call(conn, opts)
  end
end
```

## Authorizing Endpoints

We can authorize a Phoenix controller using the `Authex.Plug.Authorization` plug. This plug checks the scopes of the token and compares them to the "permits" allowed for the controller action.

Authorization works by combining the "permits" with the "type" of request that is being made.

For example, with our controller below, we are permitting "user" and "admin" access. The show action would be a `GET` request, and would therefore be a "read" type.

Requests are bucketed under the following types:

  * "GET" - "read"
  * "HEAD" - "read"
  * "PUT" - "write"
  * "PATCH" - "write"
  * "POST" - "write"
  * "DELETE" - "delete"

So, in order to access the show action, our token would require one of the following scopes: `["user/read", "admin/read"]`. Or, the token would require `["user/write", "admin/write"]` to access the update action.

By default, if authorization fails, the plug sends the conn to the `Authex.Plug.Forbidden` plug. This plug will put a `403` status into the conn with the body `"Forbidden"`. We can configure our own forbidden plug by passing it as an option to the `Authex.Plug.Authorization` plug.

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
    opts = Authex.Plug.Authentication.init([unauthorized: MyApp.UnauthorizedPlug])
    Authex.Plug.Authentication.call(conn, opts)
  end

  defp authorize(conn, opts) do
    opts = Authex.Plug.Authorization.init([forbidden: MyApp.ForbiddenPlug])
    Authex.Plug.Authorization.call(conn, opts)
  end
end
```

## Blacklisting Tokens

WIP