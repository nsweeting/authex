# Authex

[![Build Status](https://travis-ci.org/nsweeting/authex.svg?branch=master)](https://travis-ci.org/nsweeting/authex)
[![Authex Version](https://img.shields.io/hexpm/v/authex.svg)](https://hex.pm/packages/authex)

Authex is a simple JWT authentication and authorization library for Elixir.

## Installation

The package can be installed by adding `authex` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:authex, "~> 1.0"},

    # Add plug dependency if you want to use Authex plugs.
    {:plug, "~> 1.0"}
  ]
end
```

## Documentation

See [HexDocs](https://hexdocs.pm/authex) for additional documentation.

## Example

To get started, we must define our auth module:

```elixir
defmodule MyApp.Auth do
  use Authex, otp_app: :my_app

  # Use the runtime init callback to dynamically set our secret.
  def init(config) do
    secret = System.get_env("AUTH_SECRET") || "secret"
    config = Keyword.put(config, :secret, secret)

    {:ok, config}
  end
end
```

And add it to your supervision tree:

```elixir
children = [
  MyApp.Auth
]
```

We can then create, sign, and verify tokens:

```elixir
token = MyApp.Auth.token(sub: 1, scopes: ["admin/read"])
compact_token = MyApp.Auth.sign(token)
{:ok, token} = MyApp.Auth.verify(compact_token)
```

Please check out the documentation for more advanced features like serializers,
repositories and integration with plugs.

## Features

- Easy to integrate with almost any app.
- Handles both authentication + authorization.
- Compatible with umbrella apps.
- Convert data to and from tokens via serializers.
- Handle persistence for things like blacklists.
- Batteries included for plug integration.