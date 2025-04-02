{
  description = "A flake that provides the proxytunnel command";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = {
    self,
    nixpkgs,
    ...
  }: let
    # TODO: Check functionality and add support for other architectures.
    supportedSystems = ["x86_64-linux"];
    forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

    mkProxyTunnel = system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in
      pkgs.stdenv.mkDerivation {
        pname = "proxytunnel";

        version = "1.0.0";

        src = ./.;
        nativeBuildInputs = [pkgs.gnumake];
        buildInputs = [pkgs.openssl];

        buildPhase = ''
          make
        '';

        installPhase = ''
          mkdir -p $out/bin
          cp ./proxytunnel $out/bin
        '';
      };
  in {
    packages = forAllSystems mkProxyTunnel;

    defaultPackage = forAllSystems (system: self.packages.${system});

    devShells = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in
      pkgs.mkShell {
        packages = [self.defaultPackage.${system}];
      });
  };
}
