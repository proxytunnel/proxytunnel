{
  use-ssl ? true,
  gnu-system ? true,
  set-proc-title ? true,
  pkgs,
}: let
  optflags = "${
    if use-ssl
    then "-DUSE_SSL"
    else ""
  } ${
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
