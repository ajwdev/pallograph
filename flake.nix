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

    # Everything needed to build and test. CI uses only this, so keep it lean.
    buildInputs = with pkgs; [
      (rust.stable.withComponents [
        "cargo"
        "clippy"
        "rust-src"
        "rustc"
        "rustfmt"
      ])
      pkg-config
      z3
      llvmPackages.libclang
    ];

    env = {
      Z3_SYS_Z3_HEADER = "${pkgs.z3.dev}/include/z3.h";
      LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
      LD_LIBRARY_PATH = "${pkgs.z3.lib}/lib";

      RUST_BACKTRACE = 1;
    };
  in {
    devShells.ci = pkgs.mkShell (env // { inherit buildInputs; });

    devShells.default = pkgs.mkShell (env // {
      buildInputs = buildInputs ++ (with pkgs; [
        rust.stable.rust-analyzer
        kind
        kubectl
        kwok
      ]);
    });
  });
}
