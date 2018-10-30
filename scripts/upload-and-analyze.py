import os
import sys
import argparse

import progressbar

from snappycap import const
from snappycap import utils
from snappycap import interfaces


def parse_commandline():
    args = argparse.ArgumentParser(description=const.DESCRIPTION)
    args.add_argument(
        '--path',
        help='One or more paths to pcap or directory of pcaps.',
        nargs='+',
        required='--analyze' in sys.argv
    )
    args.add_argument(
        '--analyze',
        help="If included, capture will be uploaded for analysis to PacketTotal.com.",
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
    if len(sys.argv) == 1:
        utils.print_pt_ascii_logo()
    args = parse_commandline()
    analyze_paths = []
    if args.list_pcaps:
        interfaces.print_submission_status()
    elif args.export_pcaps:
        interfaces.export_submissions_status()
    if not args.path:
        sys.exit(0)
    for path in args.path:
        if os.path.isdir(path):
            for f in os.listdir(path):
                f = os.path.join(path, f)
                if not os.path.isfile(f):
                    continue
                with open(f, 'rb') as fh:
                    if not utils.is_packet_capture(fh.read()):
                        continue
                    fh.seek(0)
                    if len(fh.read(50000001)) > const.PT_MAX_BYTES:
                        continue
                analyze_paths.append(f)
        elif os.path.isfile(path):
            with open(path, 'rb') as f:
                if not utils.is_packet_capture(path.read()):
                    continue
                f.seek(0)
                if len(path.read(50000001)) > const.PT_MAX_BYTES:
                    continue
                analyze_paths.append(path)
    interfaces.Database().initialize_database()
    for path in progressbar.progressbar(analyze_paths):
        pcap = interfaces.Capture(filepath=path)
        try:
            pcap.upload()
            pcap.save()
        except Exception:
            print("Upload failed!")
            sys.exit(1)
    sys.exit(0)



