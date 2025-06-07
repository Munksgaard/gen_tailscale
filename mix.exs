defmodule GenTailscale.MixProject do
  use Mix.Project

  def project do
    [
      app: :gen_tailscale,
      version: "0.1.0",
      elixir: "~> 1.18",
      make_cwd: "native",
      make_clean: ["clean"],
      compilers: [:elixir_make] ++ Mix.compilers(),
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
       git: "https://github.com/tailscale/libtailscale.git",
       rev: "cab04836d0520f90efffd851554fb5f1bb1c6835",
       app: false,
       compile: false,
       runtime: false},
      {:elixir_make, "~> 0.9.0", runtime: false}
    ]
  end
end
