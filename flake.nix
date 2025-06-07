{
  inputs = { nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable"; };

  outputs = inputs:
    let
      supportedSystems =
        [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forEachSupportedSystem = f:
        inputs.nixpkgs.lib.genAttrs supportedSystems
        (system: f { pkgs = import inputs.nixpkgs { inherit system; }; });

    in {
      devShells = forEachSupportedSystem ({ pkgs }: {
        default = pkgs.mkShell {
          packages =
            (if pkgs.stdenv.isLinux then [ pkgs.inotify-tools ] else [ ]) ++
              [ pkgs.elixir pkgs.go ];
        };
      });
    };
}
