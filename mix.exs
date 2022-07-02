defmodule Firma.MixProject do
  use Mix.Project

  def project do
    [
      app: :firma,
      version: "0.1.0",
      elixir: "~> 1.13",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ok, "~> 2.3"},
      {:jason, "~> 1.3"},
      {:jose, "~> 1.11"},
      {:joken, "~> 2.5.0"},
      {:x509, "~> 0.8"}
    ]
  end
end
