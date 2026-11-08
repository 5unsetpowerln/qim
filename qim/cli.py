"""Command line interface."""
import argparse
import datetime

from qim import image, profiles


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

    args = parser.parse_args(argv)
    if args.command == "image" and args.image_command == "build":
        print(image.build(args.profile, args.date or image.default_date(), args.name))
    return 0
