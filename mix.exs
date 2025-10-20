defmodule Authex.Mixfile do
  use Mix.Project

  @version "2.3.0"

  def project do
    [
      app: :authex,
      version: @version,
      elixir: "~> 1.5",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      name: "Authex",
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :plug]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp description do
    """
    Authex is a simple and opinionated JWT authentication and authorization library.
    """
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README*"],
      maintainers: ["Nicholas Sweeting"],
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/nsweeting/authex"}
    ]
  end

  defp docs do
    [
      main: "Authex",
      source_ref: "v#{@version}",
      canonical: "http://hexdocs.pm/authex",
      extras: ["README.md"],
      main: "readme",
      source_url: "https://github.com/nsweeting/authex",
      groups_for_modules: [
        Plugs: [
          Authex.Plug.Authentication,
          Authex.Plug.Authorization,
          Authex.Plug.Unauthorized,
          Authex.Plug.Forbidden
        ]
      ]
    ]
  end

  defp deps do
    [
      {:keyword_validator, "~> 2.0"},
      {:jose, "~> 1.11"},
      {:jason, "~> 1.0", optional: true},
      {:plug, "~> 1.12", optional: true},
      {:ex_doc, "~> 0.28", only: :dev, runtime: false}
    ]
  end
end
