let 
  nixpkgs = fetchTarball "https://github.com/NixOS/nixpkgs/tarball/nixos-25.05";
  pkgs = import nixpkgs { config = {}; overlays = []; };
  project = pkgs.lib.sources.cleanSource ./.;
  manifest = pkgs.lib.importTOML "${project.outPath}/Cargo.toml";
  package = manifest.package;

  buildPackage = {}: pkgs.rustPlatform.buildRustPackage rec {
    pname = package.name;
    version = package.version;
    src = project;
    
    cargoLock = {
      lockFile = "${project.outPath}/Cargo.lock";
    };

    meta = with pkgs.lib; {
      description = package.description;
      homepage = package.homepage;
      maintainers = package.authors;
    };
  };
in
  {
    jgpg = pkgs.callPackage buildPackage {};
  }