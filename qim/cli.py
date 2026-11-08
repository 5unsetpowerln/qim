"""Command line interface."""
import argparse
import datetime
from pathlib import Path

from qim import image, profiles, run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="qim", description="Quarantined Installation Monitor")
    commands = parser.add_subparsers(dest="command", required=True)

    image_commands = commands.add_parser("image", help="manage base guest images").add_subparsers(
        dest="image_command", required=True)
    build = image_commands.add_parser("build", help="build a base image from a dated Arch Linux Archive snapshot")
    build.add_argument("--profile", default="default", choices=sorted(profiles.PROFILES))
    build.add_argument("--date", type=datetime.date.fromisoformat,
                       help="snapshot date YYYY-MM-DD (default: yesterday, UTC)")
    build.add_argument("--name", help="image name (default: <profile>-<date>)")

    run_parser = commands.add_parser("run", help="run a command in a guest and collect what it did")
    run_parser.add_argument("--image", required=True, help="base image name (see qim image build)")
    run_parser.add_argument("--output", required=True, type=Path, help="output directory (must not exist)")
    run_parser.add_argument("--timeout", type=int, default=3600, help="seconds before the command is killed")
    run_parser.add_argument("--memory", type=int, default=8192, help="guest memory in MiB")
    run_parser.add_argument("--cpus", type=int, default=8)
    run_parser.add_argument("argv", nargs=argparse.REMAINDER, metavar="-- COMMAND ...")

    args = parser.parse_args(argv)
    if args.command == "image":
        print(image.build(args.profile, args.date or image.default_date(), args.name))
        return 0
    command = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
    if not command:
        parser.error("run: give the command after --")
    return run.run(args.image, command, args.output, args.timeout, args.memory, args.cpus)
