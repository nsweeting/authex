# Authex

[![Build Status](https://travis-ci.org/nsweeting/authex.svg?branch=master)](https://travis-ci.org/nsweeting/authex)
[![Authex Version](https://img.shields.io/hexpm/v/authex.svg)](https://hex.pm/packages/authex)

Authex is a simple JWT authentication and authorization library for Elixir.

## Installation

The package can be installed by adding `authex` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:authex, "~> 0.2.1"}
  ]
end
```

## Documentation

See [HexDocs](https://hexdocs.pm/authex) for additional documentation.

## Creating an Auth module

We can start off by creating our Auth module. This is simply a module that uses `Authex`.

```elixir
defmodule MyApp.Auth do
  use Authex, otp_app: :my_app
end
```

## Configuration

We will also need to configure our Auth module. At a minimum, we need to add a secret from which our tokens will be signed with. There is a convenient mix task available for this.

```
mix authex.gen.secret
```

We should now add this secret to our config. In production this should be set via an env var.
There is the `set_secret/1` helper function available for this task. We should call this in our
application start to dynamically set the secret.

```elixir
"AUTH_ENV_VAR" |> System.get_env() |> MyApp.Auth.set_secret()
```

Alternatively, we can simply hard code it in our config files.

```elixir
config :my_app, MyApp.Auth, [
  # REQUIRED
  # The secret used to sign tokens with.
  secret: "mysecret",

  # OPTIONAL
  # A blacklist module, or false if disabled.
  blacklist: false,
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

At the heart of token creation is the `Authex.Token` struct. This struct is simply a wrapper around the typical JWT claims. The only additional item is the `:scopes` and `:meta` key.

We can easily create `Authex.Token` structs using the `token/2` function.

```elixir
MyApp.Auth.token(sub: 1, scopes: ["admin/read"])
```

The above would create an `Authex.Token` struct for a user with an id of 1, and with "admin/read" authorization.

## Signing Tokens

Once we have a `Authex.Token` struct, we can sign it to create a compact token binary. This is what we will use for authentication and authorization for our API.

```elixir
[sub: 1, scopes: ["admin/read"]]
|> MyApp.Auth.token()
|> MyApp.Auth.sign()
```

## Verifying Tokens

Once we have a compact token binary, we can verify it and turn it back to an `Authex.Token` struct.

```elixir
[sub: 1, scopes: ["admin/read"]]
|> MyApp.Auth.token()
|> MyApp.Auth.sign()
|> MyApp.Auth.verify()
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
    MyApp.Auth.token(sub: id, scopes: scopes)
  end
end
```

We will then want to define our serializer in our config.

```elixir
config :my_app, MyApp.Auth, [
  # ...other config

  serializer: MyApp.TokenSerializer,
]
```

We can now easily create tokens and compact tokens from our `User` structs using the `for_token/1` and `for_compact_token/1` functions.

```elixir
user = %MyApp.User{id: 1, scopes: []}
MyApp.Auth.for_token(user) # returns an Authex.Token struct
MyApp.Auth.for_compact_token(user) # returns a compact token
```

We can also turn tokens and compact tokens back into our `User` structs using the `from_token/1` and `from_compact_token/1` functions.

```elixir
user = %MyApp.User{id: 1, scopes: []}

token = MyApp.Auth.for_token(user)
MyApp.Auth.from_token(token)

compact_token = MyApp.Auth.for_compact_token(user)
MyApp.Auth.from_compact_token(compact_token)
```

## Authenticating Endpoints

We can authenticate a Phoenix controller using the `Authex.AuthenticationPlug` plug. This plug looks for the `Authenicate: Bearer mytoken` header. It will then verify, and deserialize the token using our configured serializer.

We can access our current user from the conn using the `current_user/1` function.

By default, if authentication fails, the plug sends the conn to the `Authex.UnauthorizedPlug` plug. This plug will put a `401` status into the conn with the body `"Unauthorized"`. We can configure our own unauthorized plug by passing it as an option to the `Authex.AuthenticationPlug` plug or
through our config.

```elixir
config :my_app, MyApp.Auth, [
  # ...other config

  unauthorized: MyApp.UnauthorizedPlug
]
```

And we can use the plug as follows:

```elixir
defmodule MyApp.Web.UserController do
  use MyApp.Web, :controller

  plug Authex.AuthenticationPlug, auth: MyApp.Auth

  def show(conn, _params) do
    with {:ok, %{id: id}} <- MyApp.Auth.current_user(conn),
         {:ok, user} <- MyApp.Users.get(id)
    do
      render(conn, "show.json", user: user)
    end
  end
end
```

## Authorizing Endpoints

We can authorize a Phoenix controller using the `Authex.AuthorizationPlug` plug. This plug checks the scopes of the token and compares them to the "permits" allowed for the controller action.

Authorization works by combining the "permits" with the "type" of request that is being made.

For example, with our controller below, we are permitting "user" and "admin" access. The show action would be a `GET` request, and would therefore be a "read" type.

Requests are bucketed under the following types:

  * GET - read
  * HEAD - read
  * PUT - write
  * PATCH - write
  * POST - write
  * DELETE - delete

So, in order to access the show action, our token would require one of the following scopes: `["user/read", "admin/read"]`. Or, the token would require `["user/write", "admin/write"]` to access the update action.

By default, if authorization fails, the plug sends the conn to the `Authex.ForbiddenPlug` plug. This plug will put a `403` status into the conn with the body `"Forbidden"`. We can configure our own forbidden plug by passing it as an option to the `Authex.AuthorizationPlug` plug or through our config.

```elixir
config :my_app, MyApp.Auth, [
  # ...other config

  forbidden: MyApp.ForbiddenPlug
]
```

```elixir
defmodule MyApp.Web.UserController do
  use MyApp.Web, :controller

  plug Authex.AuthenticationPlug, auth: MyApp.Auth
  plug Authex.AuthorizationPlug, auth: MyApp.Auth, permits: ["user", "admin"]

  def show(conn, _params) do
    with {:ok, %{id: id}} <- MyApp.Auth.current_user(conn),
         {:ok, user} <- MyApp.Users.get(id)
    do
      render(conn, "show.json", user: user)
    end
  end
end
```

## Blacklisting Tokens

Authex includes the ability to blacklist tokens through their jti claim. The recommended way to do this is with the with [Authex.Blacklist.Redis](https://github.com/nsweeting/authex_blacklist_redis) library. As you can tell by its name, it uses Redis as the blacklist storage medium. Details on setup and config are available for its repo.

To blacklist a token, simply pass an `Authex.Token` struct, or binary jti claim to `blacklist/1`. To check whether a token is blacklisted, simply call `blacklisted?/1` with a token or binary jti.

```elixir
token = MyApp.Auth.token()
MyApp.Auth.blacklist(token)
MyApp.Auth.blacklisted?(token)
MyApp.Auth.unblacklist(token)
```

By default, if we configure a blacklist via the config options, our `verify/1` process will also check the blacklist. The same process is used with the `Authex.AuthorizationPlug` plug.

Alternatively, you can setup your own blacklist by `use`ing the `Authex.Blacklist` behaviour. The module must implement `handle_get/1`, `handle_set/1` and `handle_del/1`. For an example usage (but not production usable) - check out a [basic example](https://github.com/nsweeting/authex/blob/master/test/support/blacklist.ex).

## Banning Subjects

Info to come
