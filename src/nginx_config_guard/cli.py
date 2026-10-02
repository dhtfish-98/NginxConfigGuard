import argparse
import json
from . import __version__
from .review import review_config
from .report import Limits, Report


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('invalid_arguments')


def main(argv=None):
    parser = SafeParser(description='Offline local Nginx configuration policy review; no execution, network or include expansion.')
    parser.add_argument('config', help='Exactly one explicitly named local regular configuration file')
    parser.add_argument('--version', action='version', version=__version__)
    try:
        args = parser.parse_args(argv)
    except ValueError:
        rejected = Report(Limits())
        rejected.add('OPEN', 'invalid_arguments', 'Arguments are outside the supported CLI profile; private details suppressed.', incomplete=True)
        report = rejected.finish()
    else:
        report = review_config(args.config)
    print(json.dumps(report, ensure_ascii=True, separators=(',', ':')))
    return {'PASS': 0, 'FAIL': 1, 'OPEN': 2}[report['status']]
