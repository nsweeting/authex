# Authex

[![Build Status](https://travis-ci.org/nsweeting/authex.svg?branch=master)](https://travis-ci.org/nsweeting/authex)
[![Authex Version](https://img.shields.io/hexpm/v/authex.svg)](https://hex.pm/packages/authex)

Authex is a simple JWT authentication and authorization library for Elixir.

## Installation

The package can be installed by adding `authex` to your list of dependencies in `mix.exs`.

In addition, we must also add a JSON encoder/decoder. [Jason](https://github.com/michalmuskala/jason) is recommended. But any of these will work: [jiffy](https://github.com/davisp/jiffy), [jsone](https://github.com/sile/jsone), [jsx](https://github.com/talentdeficit/jsx), [ojson](https://github.com/potatosalad/erlang-ojson), [Poison](https://github.com/devinus/poison).

Finally, if you wish to use any of the plug functionality, make sure to add the plug dependency.

```elixir
def deps do
  [
    {:authex, "~> 2.0"},
    {:jason, "~> 1.0"},
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
  use Authex

  def start_link(opts \\\\ []) do
    Authex.start_link(__MODULE__, opts, name: __MODULE__)
  end

  # Callbacks

  @impl Authex
  def init(opts) do
    # Add any configuration listed in Authex.start_link/3

    secret = System.get_env("AUTH_SECRET") || "foobar"
    opts = Keyword.put(opts, :secret, secret)

    {:ok, opts}
  end

  @impl Authex
  def handle_for_token(%MyApp.User{} = resource, opts) do
    {:ok, [sub: resource.id, scopes: resource.scopes], opts}
  end

  def handle_for_token(_resource, _opts) do
    {:error, :bad_resource}
  end

  @impl Authex
  def handle_from_token(token, _opts) do
    # You may want to perform a database lookup for your user instead
    {:ok, %MyApp.User{id: token.sub, scopes: token.scopes}}
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
token = Authex.token(MyApp.Auth, sub: 1, scopes: ["admin/read"])
compact_token = Authex.sign(MyApp.Auth, token)
{:ok, token} = Authex.verify(MyApp.Auth, compact_token)
```

We can also convert resources to and from tokens.

```elixir
token = Authex.for_token(MyApp.Auth, user)
compact_token = Authex.sign(MyApp.Auth, token)
{:ok, token} = Authex.verify(MyApp.Auth, compact_token)
{:ok, user} = Authex.from_token(MyApp.Auth, token)
```

Please check out the documentation for more advanced features.

## Features

- Easy to integrate with almost any app.
- Handles both authentication + authorization.
- Convert data to and from tokens.
- Handle persistence for things like blacklists.
- Batteries included for plug integration.