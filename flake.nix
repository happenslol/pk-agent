{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    nixpkgs,
    rust-overlay,
    ...
  }: let
    overlays = [(import rust-overlay)];
    system = "x86_64-linux";
    pkgs = import nixpkgs {inherit system overlays;};

    rustPlatform = pkgs.makeRustPlatform {
      cargo = pkgs.rust-bin.stable.latest.minimal;
      rustc = pkgs.rust-bin.stable.latest.minimal;
    };

    nativeBuildInputs = with pkgs; [pkg-config];
    buildInputs = with pkgs; [gtk4 gtk4-layer-shell];
  in {
    packages.${system}.default = rustPlatform.buildRustPackage {
      name = "pk-agent";
      src = ./.;

      cargoLock = {lockFile = ./Cargo.lock;};
      cargoHash = pkgs.lib.fakeHash;

      inherit nativeBuildInputs buildInputs;
    };

    devShells.${system}.default = pkgs.mkShell {
      inherit nativeBuildInputs buildInputs;
    };
  };
}
