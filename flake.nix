{
  description = "Basic flake that provides proxytunnel as a package or as a binary in a nix shell";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = inputs @ {flake-parts, ...}:
    flake-parts.lib.mkFlake {inherit inputs;} {
      # TODO: Add support for more systems once checked.
      systems = ["x86_64-linux"];

      imports = [inputs.flake-parts.flakeModules.easyOverlay];

      perSystem = {
        config,
        pkgs,
        ...
      }: {
        overlayAttrs = {
          inherit (config.packages) proxytunnel;
        };

        packages.proxytunnel = pkgs.callPackage ./nix/proxytunnel.nix {};
        packages.default = config.packages.proxytunnel;

        devShells.default = pkgs.mkShell {
          packages = [config.packages.default];
        };
      };
    };
}
