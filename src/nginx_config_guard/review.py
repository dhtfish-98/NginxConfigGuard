"""Public API for explicit local configuration snapshots."""
from .model import Model
from .parser import Parser
from .report import Limits, Report, Stop, read_local


def review_config(path, *, limits=None):
    if limits is None:
        limits = Limits()
    elif type(limits) is not Limits:
        raise TypeError('limits must be Limits or None')
    limits.validate()
    report = Report(limits)
    try:
        data = read_local(path, report)
        Model(Parser(data, report).parse(), report).run()
    except Stop:
        pass
    except (OSError, ValueError, UnicodeError) as exc:
        try:
            report.add('OPEN', 'input_error', f'Observation stopped on {type(exc).__name__}; private details suppressed.', incomplete=True)
        except Stop:
            pass
    return report.finish()
