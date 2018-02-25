defmodule Authex.Mixfile do
  use Mix.Project

  @version "0.2.1"

  def project do
    [
      app: :authex,
      version: @version,
      elixir: "~> 1.5",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
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
      links:  %{"GitHub" => "https://github.com/nsweeting/authex"}
    ]
  end

  defp docs do
    [
      extras: ["README.md"],
      main: "readme",
      source_url: "https://github.com/nsweeting/authex"
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:jose, "~> 1.8"},
      {:uuid, "~> 1.1" },
      {:poison, "~> 3.1"},
      {:plug, "~> 1.0"},
      {:ex_doc, ">= 0.0.0", only: :dev}
    ]
  end
end
