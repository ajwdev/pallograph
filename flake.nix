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
      # Builds tools/rbac-oracle, which generates the RBAC compatibility
      # test data (hack/rbac-compat-gen.sh).
      go
    ];

    env = {
      Z3_SYS_Z3_HEADER = "${pkgs.z3.dev}/include/z3.h";
      LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
      LD_LIBRARY_PATH = "${pkgs.z3.lib}/lib";

      RUST_BACKTRACE = 1;
    };
    # Release builds use nixpkgs' rustc rather than fenix so that pkgsStatic
    # (musl) works without a cross toolchain.
    mkPallograph = p: z3: p.rustPlatform.buildRustPackage {
      pname = "pallograph";
      version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;
      src = p.lib.cleanSource ./.;
      cargoLock = {
        lockFile = ./Cargo.lock;
        # Fetch git dependencies (mangle-rs) by their pinned rev instead of
        # keeping an outputHashes entry per crate in step with every bump.
        allowBuiltinFetchGit = true;
      };
      cargoBuildFlags = [ "--bin" "pallograph" ];

      nativeBuildInputs = [ p.buildPackages.pkg-config p.rustPlatform.bindgenHook ];
      buildInputs = [ z3 ];
      Z3_SYS_Z3_HEADER = "${z3.dev}/include/z3.h";

      # CI already runs the tests, and the RBAC compat test needs Go.
      doCheck = false;
    };

    pallograph = mkPallograph pkgs pkgs.z3;
  in {
    packages = {
      default = pallograph;
    } // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux (let
      # z3's own test runner fails to spawn two tests under musl
      # ("Failed to start child process"); every test that runs passes.
      staticZ3 = pkgs.pkgsStatic.z3.overrideAttrs { doCheck = false; };
      static = (mkPallograph pkgs.pkgsStatic staticZ3).overrideAttrs {
        # libz3.a is C++; z3-sys only adds the C++ runtime when it builds z3
        # itself (the z3-static feature). The musl target defaults to
        # static-pie, but nixpkgs' static libstdc++.a is not PIC, so build a
        # plain static binary.
        RUSTFLAGS = "-C link-arg=-lstdc++ -C link-arg=-lc -C relocation-model=static";

        # The static stdenv records buildInputs as propagated, which would pull
        # all of z3 into the closure. The binary needs nothing at runtime.
        postFixup = "rm -r $out/nix-support";
        allowedReferences = [ ];
      };
    in {
      inherit static;

      # Root filesystem for the Dockerfile. busybox provides the `sh` that
      # shell datasources run through.
      container = pkgs.buildEnv {
        name = "pallograph-container";
        paths = [ static pkgs.pkgsStatic.busybox pkgs.cacert ];
      };
    });

    devShells.ci = pkgs.mkShell (env // { inherit buildInputs; });

    devShells.default = pkgs.mkShell (env // {
      buildInputs = buildInputs ++ (with pkgs; [
        rust.stable.rust-analyzer
        kind
        kubectl
        kwok
        # Used to regenerate src/builtins.txt (see its header).
        jq
        ast-grep
        # Used by hack/fetch-fixtures.sh and hack/publish-fixtures.sh.
        zstd
      ]);
    });
  });
}
