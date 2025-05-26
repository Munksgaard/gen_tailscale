defmodule GenTailscale.MixProject do
  use Mix.Project

  def project do
    [
      app: :gen_tailscale,
      version: "0.1.0",
      language: :erlang,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:libtailscale,
       git: "https://github.com/Munksgaard/libtailscale.git", branch: "elixir", subdir: "elixir"}
    ]
  end
end
