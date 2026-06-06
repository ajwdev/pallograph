{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, utils, nixpkgs, fenix, }: utils.lib.eachDefaultSystem (system: let
    pkgs = nixpkgs.legacyPackages.${system};
    rust = fenix.packages.${system};
  in {
    devShell = pkgs.mkShell {
      buildInputs = with pkgs; [
        (rust.latest.withComponents [
          "cargo"
          "clippy"
          "rust-src"
          "rustc"
          "rustfmt"
        ])
        rust.latest.rust-analyzer
        pkg-config
        kind
        kubectl
        kwok
        z3
        llvmPackages.libclang
      ];

      Z3_SYS_Z3_HEADER = "${pkgs.z3.dev}/include/z3.h";
      LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
      LD_LIBRARY_PATH = "${pkgs.z3.lib}/lib";

      RUST_BACKTRACE = 1;
    };
  });
}
