from json import dump
from copy import deepcopy

from sextant import chronicle
from sextant import navigator


chronicle_layer = deepcopy(navigator.layer_template)
chronicle_layer['name'] = 'chronicle-siem'
chronicle_layer['description'] = 'TTPs mapped from Chronicle SIEM'
chronicle_layer['techniques'] = chronicle.get_techniques(
    'keyfile.json', 
    '#5789ed', 
    'Chronicle SIEM'
)

with open('layer.json', 'w') as f:
    dump(chronicle_layer, f)
