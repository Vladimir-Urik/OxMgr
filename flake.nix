{
  description = "Oxmgr - lightweight language-agnostic process manager";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          oxmgr = pkgs.rustPlatform.buildRustPackage {
            pname = "oxmgr";
            version = (pkgs.lib.importTOML ./Cargo.toml).package.version;

            src = ./.;

            cargoLock = {
              lockFile = ./Cargo.lock;
            };

            postPatch = ''
              # Fix sysinfo 0.40 compatibility on upstream master if not yet patched
              if grep -q 'system: System::new_all(),' src/process_manager.rs; then
                substituteInPlace src/process_manager.rs \
                  --replace-fail 'system: System::new_all(),' 'system: System::new_all()?,'
              fi
              if grep -q 'let mut system = System::new_all();' src/process_manager/runtime.rs; then
                substituteInPlace src/process_manager/runtime.rs \
                  --replace-fail 'let mut system = System::new_all();' 'let Ok(mut system) = System::new_all() else { return false; };'
              fi
            '';

            nativeCheckInputs = [
              pkgs.gitMinimal
            ];

            buildInputs = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isDarwin [
              pkgs.apple-sdk
            ];

            meta = {
              description = "Oxmgr - lightweight language-agnostic process manager";
              homepage = "https://github.com/Vladimir-Urik/OxMgr";
              license = pkgs.lib.licenses.mit;
              mainProgram = "oxmgr";
            };
          };
          default = self.packages.${system}.oxmgr;
        }
      );

      apps = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = {
            type = "app";
            program = "${self.packages.${system}.oxmgr}/bin/oxmgr";
            meta = {
              description = self.packages.${system}.oxmgr.meta.description;
            };
          };
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            inputsFrom = [ self.packages.${system}.oxmgr ];
            packages = with pkgs; [
              cargo
              rustc
              rust-analyzer
              clippy
              rustfmt
            ];
          };
        }
      );
    };
}
