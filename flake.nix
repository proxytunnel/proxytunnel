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
    pkgs = nixpkgs.legacyPackages."x86_64-linux";
  in {
    packages.x86_64-linux.default = pkgs.stdenv.mkDerivation {
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

    devShells.x86_64-linux.default = pkgs.mkShell {
      packages = [self.packages.x86_64-linux.default];
    };
  };
}
