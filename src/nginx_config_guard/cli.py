import argparse
import json
from . import __version__
from .review import review_config


def main(argv=None):
    parser = argparse.ArgumentParser(description='Offline local Nginx configuration policy review; no execution, network or include expansion.')
    parser.add_argument('config', help='Exactly one explicitly named local regular configuration file')
    parser.add_argument('--version', action='version', version=__version__)
    args = parser.parse_args(argv)
    report = review_config(args.config)
    print(json.dumps(report, ensure_ascii=True, separators=(',', ':')))
    return {'PASS': 0, 'FAIL': 1, 'OPEN': 2}[report['status']]
