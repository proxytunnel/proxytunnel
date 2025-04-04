# Short guide to installing proxytunnel

On most modern **unix systems**, use the normal Makefile, possibly uncommenting
the section related to your system (darwin/cygwin/solaris/openbsd)

If you want to enable setproctitle functionality, add a CFLAGS define
-DSETPROCTITLE (uncomment sample in Makefile)

to build simply run `make` and optionally `make install`.
If you manually want to install, copy proxytunnel to /usr/local/bin
and optionally the manual-page from the debian-subdirectory to your manpath

# Nix Flakes

> NOTE: The Nix Flake installation currently only supports the `x86_64-linux` platform, and has not been tested on other architectures.

A simple Nix Flake is included to allow for use via flake inputs. To create a temporary Nix Shell with access to the `proxytunnel` binary, you can run the command:
```console
nix develop github:proxytunnel/proxytunnel
```
If you instead want to include it as a flake input, the following `flake.nix` shows how to do so:
```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # Add proxytunnel as an input
    proxytunnel.url = "github:proxytunnel/proxytunnel";
  };

  outputs = {
    nixpkgs,
    proxytunnel,
    ...
  }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs {
      system = "x86_64-linux";
      overlays = [
          # Add proxytunnel's default features to your nixpkgs
          proxytunnel = proxytunnel.overlays.default;

          # For a full list of override options, see `nix/proxytunnel.nix`
      ];
    };
  in {
    devShells.${system}.default = pkgs.mkShell {
      packages = [ 
        # Make the `proxytunnel` binary available in a Nix Shell
        # The above overlay adds it to nixpkgs. Without the overlay, use proxytunnel.packages.${system}.default
        pkgs.proxytunnel

        # And include any other packages as desired...
        pkgs.gcc
        # ...
      ];
    };
  };
}
```

# msys2

To install msys2 with [chocolatey](https://chocolatey.org/install):
```
C:\> choco install -y msys2
```

To switch to msys2 shell:
```
C:\> C:\\tools\\msys64\\msys2_shell.cmd -defterm -no-start -msys2
me@mymachine MSYS ~
```

To install dependancy:
```
me@mymachine MSYS ~ pacman --sync --noconfirm --needed mingw-w64-x86_64-toolchain gcc make openssl openssl-devel zip xmlto asciidoc
```

To build with msys2 :
```
me@mymachine MSYS ~ make
```

To build docs with msys2 :
```
me@mymachine MSYS ~ make docs
```

To use `proxytunnel.exe` from windows, copy msys and openssl dll to the same directory as proxytunnel.exe(use `ldd` cmd to see what dll are used by `proxytunnel.exe`) cmd:
```
me@mymachine MSYS ~ cp  /usr/bin/msys-2.0.dll /usr/bin/msys-crypto-1.1.dll /usr/bin/msys-ssl-1.1.dll /usr/bin/msys-z.dll .
```

# Cygwin :

Currently cygwin's openssl isn't in a compilable state, change md4.h and
md5.h in /usr/include
and replace 'size_t' with 'unsigned long'

To link the final executable:
gcc -o proxytunnel *.o /lib/libcrypto.dll.a /lib/libssl.dll.a

To run, copy the required dll's from the cygwin-bin dir to the windows
system dir, or the proxytunnel directory (cygcrypto-0.9.8.dll,
cygssl-0.9.8.dll, cygwin1.dll )

Setproctitle doesn't work on cygwin (afaik)
