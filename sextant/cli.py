#!/usr/bin/env python3

'''
Implements the Command-line Interface routines.
'''

from argparse import ArgumentParser
from datetime import datetime
from json import dump
from copy import deepcopy

from sextant import chronicle
from sextant import navigator


parser = ArgumentParser(description='Detection rules to MITRE ATT&CK Navigator layer')
parser.add_argument(
    '--input', '-i',
    required=True, 
    choices=['chronicle'],
    help='Source of the detection rules'
    )
parser.add_argument(
    '--auth', '-a',
    required=True,
    help='Authentication data for the input'
    )
parser.add_argument(
    '--background', '-b',
    default='7725c9',
    help='Tactics row background color'
    )
parser.add_argument(
    '--color', '-c',
    default='5789ed',
    help='Techniques background color'
    )
parser.add_argument(
    '--message', '-m',
    default='Generated by Sextant',
    help='Additional comment to Techniques'
    )
parser.add_argument(
    '--output', '-o',
    default=f'sextant-{datetime.utcnow().isoformat()}.json',
    help='Techniques background color'
    )
args = parser.parse_args()


def run():
    layer = deepcopy(navigator.layer_template)
    layer['name'] = args.input
    layer['description'] = f'TTPs mapped from {args.input}'
    layer['tacticRowBackground'] = f'#{args.background}'
    layer['techniques'] = chronicle.get_techniques(
        args.auth, 
        f'#{args.color}',
        args.message
        )

    with open(args.output, 'w') as f:
        dump(layer, f)
    print(f'Output written in {args.output}')
