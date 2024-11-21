{
  description = "flake for rustica-agent";

  outputs = {
    self,
    nixpkgs,
  }: let
    systems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    inherit (nixpkgs) lib;
    forAllSystems = f: lib.genAttrs systems (system: f system);
  in {
    packages = forAllSystems (system: let
      pkgs = import nixpkgs {inherit system;};
    in rec {
      rustica = pkgs.rustPlatform.buildRustPackage {
        pname = "rustica";
        src = self;
        version = "${lib.substring 0 8 self.lastModifiedDate}_${self.shortRev or self.dirtyShortRev}";

        nativeBuildInputs = [pkgs.pkg-config];
        buildInputs = with pkgs; [rustc cargo openssl udev pcsclite protobuf];
        cargoLock = {lockFile = self + "/Cargo.lock";};

        OPENSSL_NO_VENDOR = 1;
        CARGO_FEATURE_USE_SYSTEM_LIBS = 1;
        PROTOC = "${pkgs.protobuf}/bin/protoc";
      };
      default = rustica;
    });
    defaultPackage = forAllSystems (system: self.packages.${system}.default);

    apps = forAllSystems (system: rec {
      rustica = {
        type = "app";
        program = "${self.packages.${system}.rustica}/bin/rustica";
      };
      rustica-agent-cli = {
        type = "app";
        program = "${self.packages.${system}.rustica}/bin/rustica-agent-cli";
      };
      rustica-agent-gui = {
        type = "app";
        program = "${self.packages.${system}.rustica}/bin/rustica-agent-gui";
      };
      default = rustica-agent-cli;
    });
    defaultApp = forAllSystems (system: self.apps.${system}.default);

    overlay = final: prev: {
      inherit (self.packages.${final.system}) rustica;
    };

    devShell = forAllSystems (
      system:
        nixpkgs.legacyPackages.${system}.mkShell {
          inputsFrom = builtins.attrValues self.packages.${system};
          buildInputs = [self.packages.${system}.rustica];
        }
    );

    hmModules = rec {
      rustica-agent = {
        pkgs,
        lib,
        config,
        ...
      }: let
        cfg = config.services.rustica-agent;
      in {
        options.services.rustica-agent = {
          enable = lib.mkEnableOption "Enable rustica-agent service";
          package = lib.mkOption {
            type = lib.types.package;
            default = self.packages.${pkgs.system}.default;
            description = "The rustica package to use";
          };
          configDir = lib.mkOption {
            type = lib.types.path;
            default = "${config.home.homeDirectory}/.rusticaagent";
            description = "The directory where rustica-agent configuration is stored";
          };
          environment = lib.mkOption {
            type = lib.types.str;
            description = "The name of the environment to use (under ${cfg.configDir}/environments)";
            example = "prod";
          };
          socket = lib.mkOption {
            type = lib.types.path;
            default = "${cfg.configDir}/${cfg.environment}.sock";
          };
          extraOptions = lib.mkOption {
            type = lib.types.str;
            default = "";
            description = "Extra options to pass to rustica-agent-cli";
            example = "-s 2";
          };
        };

        config = lib.mkIf cfg.enable {
          home.packages = [cfg.package];
          home.sessionVariables = {
            SSH_AUTH_SOCK = cfg.socket;
          };
          systemd.user.services.rustica-agent = {
            Unit.Description = "Rustica-Agent SSH service";
            Install.WantedBy = ["default.target"];
            Service = {
              ExecStartPre = "${pkgs.coreutils}/bin/rm -vf ${cfg.socket}";
              ExecStart =
                "${cfg.package}/bin/rustica-agent-cli single --config ${cfg.configDir}/environments/${cfg.environment} --file ${cfg.configDir}/keys/${cfg.environment} --socket ${cfg.socket}"
                + (lib.optionalString (cfg.extraOptions != "") (" " + cfg.extraOptions));
              Restart = "on-failure";
            };
          };
        };
      };
      default = rustica-agent;
    };
  };
}
