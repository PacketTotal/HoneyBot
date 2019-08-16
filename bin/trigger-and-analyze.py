#! /usr/bin/env python3

import argparse
import sys

from honeybot.lib import interfaces, utils, const


def parse_commandline():
    args = argparse.ArgumentParser(description=const.TRIGGER_AND_ANALYZE_DESC)
    args.add_argument(
        "--interface",
        help="The name of the interface (--list-interfaces to show available)",
        type=str,
        required='--learn' in sys.argv or '--listen' in sys.argv
    )
    args.add_argument(
        '--learn',
        help="The number of seconds from which to build the known connections whitelist. "
             "Connections in this whitelist will be ignored.",
        type=int
    )
    args.add_argument(
        '--listen',
        help="If included, we will begin listening for unknown connections, "
             "and immediately starting a packet capture and uploading to PacketTotal.com for analysis.",
        action="store_true"
    )
    args.add_argument(
        '--capture-seconds',
        type=int,
        help='The number of seconds worth of network traffic to capture and analyze after a trigger has fired.',
        required='--listen' in sys.argv
    )
    args.add_argument(
        "--list-interfaces",
        help="Lists the available interfaces.",
        action="store_true"
    )
    args.add_argument(
        "--list-pcaps",
        help="Lists pcaps submitted to PacketTotal.com for analysis.",
        action="store_true"
    )
    args.add_argument(
        '--export-pcaps',
        help="Writes pcaps submitted to PacketTotal.com for analysis to a csv file.",
        action="store_true"
    )
    return args.parse_args()


if __name__ == '__main__':
    args = parse_commandline()
    if len(sys.argv) == 1:
        utils.print_pt_ascii_logo()
    if args.list_interfaces:
        utils.print_network_interaces()
    elif args.list_pcaps:
        interfaces.print_submission_status()
    elif args.export_pcaps:
        interfaces.export_submissions_status()
    elif args.learn:
        interfaces.Trigger(args.interface, capture_period_after_trigger=args.learn).learn(args.learn)
    elif args.listen:
        interfaces.Database().initialize_database()
        interfaces.Trigger(args.interface, capture_period_after_trigger=args.capture_seconds).listen_and_trigger()
    sys.exit(0)
