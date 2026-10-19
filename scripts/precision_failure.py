"""Recognize a native precision gate failure without treating it as success."""
import math
import re

_PATTERN=re.compile(r'Experiment failed: (\w+) at level (\d+): decoded error ([0-9eE+.\-]+) exceeds target ([0-9eE+.\-]+)')
_OPERATIONS={'decode_encode_a','decrypt_fresh_a','decrypt_fresh_b','decrypt_prepared_a','decrypt_prepared_b',
             'multiply_before_rescale','multiply_after_rescale','depth_square','rotate_lowest_level'}


def parse_precision_failure(text,parameters):
    lines=text.strip().splitlines()
    match=_PATTERN.fullmatch(lines[-1]) if lines else None
    if not match:return None
    operation,level,error,target=match.groups()
    try:level=int(level);error=float(error);target=float(target)
    except ValueError:return None
    if operation not in _OPERATIONS or not (math.isfinite(error) and math.isfinite(target)):
        return None
    if target!=math.ldexp(1.,-parameters['precision_bits']) or not error>target>0:
        return None
    expected={'decode_encode_a':{0},'decrypt_fresh_a':{0},'decrypt_fresh_b':{0},
              'decrypt_prepared_a':{1},'decrypt_prepared_b':{1},'multiply_before_rescale':{1},
              'multiply_after_rescale':{2},'depth_square':set(range(2,parameters['depth']+2)),
              'rotate_lowest_level':{parameters['depth']+1}}
    if level not in expected[operation]:return None
    return {'operation':operation,'level':level,'reported_absolute_error':error,'configured_target':target,
            'evidence_kind':'Native failure log; no completed experiment JSON or timing data'}
