import sys


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] == "console":          # plain `p2pssh` opens the console
        from p2pssh.config import ConfigError, load_config
        from p2pssh.console import console
        try:
            return console(load_config())
        except ConfigError as e:
            print(f"error: {e}")
            return 1
    from p2pssh.cli import main as cli_main       # `p2pssh chat ben` etc. still work
    return cli_main(argv)


if __name__ == "__main__":
    sys.exit(main())