defmodule Authex.Mixfile do
  use Mix.Project

  @version "0.3.3"

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

      # Docs
      name: "Authex",
      docs: docs()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :plug]
    ]
  end

  # Specifies which paths to compile per environment.
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
          Authex.AuthenticationPlug,
          Authex.AuthorizationPlug,
          Authex.UnauthorizedPlug,
          Authex.ForbiddenPlug
        ]
      ]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:jose, "~> 1.8"},
      {:poison, "~> 3.1"},
      {:plug, "~> 1.0", optional: true},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false}
    ]
  end
end
