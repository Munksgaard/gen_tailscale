defmodule GenTailscale.MixProject do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      app: :gen_tailscale,
      name: "GenTailscale",
      version: @version,
      elixir: "~> 1.18",
      source_url: "https://github.com/Munksgaard/gen_tailscale",
      description: description(),
      package: package(),
      deps: deps(),
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:libtailscale, "~> 0.1.0"},
      {:ex_doc, "~> 0.38", only: :dev, runtime: false, warn_if_outdated: true}
    ]
  end

  defp description do
    """
    Functionality to serve TCP servers directly on your
    [Tailscale](https://tailscale.com) network using
    [libtailscale](https://github.com/tailscale/libtailscale/).
    """
  end

  defp package do
    [
      maintainers: ["Philip Munksgaard"],
      licenses: ["Apache-2.0"],
      links: links(),
      files: [
        "src",
        "config",
        "mix.exs",
        "README*",
        "CHANGELOG*",
        "LICENSE*"
      ]
    ]
  end

  def links do
    %{
      "GitHub" => "https://github.com/Munksgaard/gen_tailscale",
      "Readme" => "https://github.com/Munksgaard/gen_tailscale/blob/v#{@version}/README.md",
      "Changelog" => "https://github.com/Munksgaard/gen_tailscale/blob/v#{@version}/CHANGELOG.md"
    }
  end

  defp docs do
    [
      source_ref: "v#{@version}",
      main: "readme",
      extras: [
        "README.md",
        "LICENSE.md",
        "CHANGELOG.md"
      ],
      formatters: ["html"],
      skip_undefined_reference_warnings_on: ["changelog", "CHANGELOG.md"]
    ]
  end
end
