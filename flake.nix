{
  description = "hook-vault — an encrypted webhook inbox";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      eachSystem = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      version = "0.4.0";
    in
    {
      packages = eachSystem (pkgs:
        let system = pkgs.stdenv.hostPlatform.system; in
        {
          hook-vault = pkgs.buildGoModule {
            pname = "hook-vault";
            inherit version;
            src = ./.;
            vendorHash = "sha256-jHD8eMt/D6T5D1BX2WG9EF+pnC50lhXrXPe5PY1f9CQ=";
            env.CGO_ENABLED = "0";
            ldflags = [ "-s" "-w" "-X" "main.version=${version}" ];
            meta = {
              description = "Encrypted webhook inbox: stores provider payloads sealed with a key it does not hold";
              license = nixpkgs.lib.licenses.mit;
              mainProgram = "hook-vault";
            };
          };
          default = self.packages.${system}.hook-vault;
        });

      devShells = eachSystem (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.go
            pkgs.postgresql_18
            pkgs.golangci-lint
            pkgs.jq
            pkgs.curl
          ];
          env.CGO_ENABLED = "0";
          shellHook = ''
            echo "hook-vault dev shell"
            echo "  integration tests need HOOKVAULT_TEST_DATABASE_URL"
          '';
        };
      });

      formatter = eachSystem (pkgs: pkgs.nixpkgs-fmt);
    };
}
