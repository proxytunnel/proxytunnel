{
  gnu-system ? true,
  set-proc-title ? true,
  pkgs,
}: let
  # TODO: Due to the way the OPENSSL_VERSION_NUMBER macro is checked, the -DUSE_SSL flag is NECESSARY
  optflags = "-DUSE_SSL ${
    if gnu-system
    then "-DHAVE_GETOPT_LONG"
    else ""
  } ${
    if set-proc-title
    then "-DSETPROCTITLE -DSPT_TYPE=2"
    else ""
  }";
in
  pkgs.stdenv.mkDerivation {
    pname = "proxytunnel";
    version = "1.12.3";
    src = ./..;

    buildInputs = [pkgs.openssl];

    buildPhase = ''
      make OPTFLAGS="${optflags}"
    '';

    installPhase = ''
      mkdir -p $out/bin
      cp ./proxytunnel $out/bin
    '';
  }
