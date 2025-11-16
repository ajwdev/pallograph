{
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    goflake.url = "github:sagikazarmark/go-flake";
    goflake.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, goflake, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;

          overlays = [ goflake.overlay ];
        };
        buildDeps = with pkgs; [ go_1_25 ];
        devDeps = with pkgs; buildDeps ++ [
          gopls
          golangci-lint
          protobuf
          protoc-gen-go
          gnumake
        ];
      in
      { devShell = pkgs.mkShell { buildInputs = devDeps; }; });
}
