{
  description = "Briar native C secret scanner development environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/5052d7ccbcfb7e4ae1586cb2ecf95a2e3707dce9";

  outputs = { nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
    in
    {
      devShells = nixpkgs.lib.genAttrs systems (system:
        let pkgs = import nixpkgs { inherit system; };
        in {
          default = pkgs.mkShell {
            packages = with pkgs; [ pkg-config gnumake python3 ];
            buildInputs = with pkgs; [ pcre2 curl json_c ];
          };
        });
    };
}
