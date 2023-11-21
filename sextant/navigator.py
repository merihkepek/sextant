#!/usr/bin/env python3

'''
Templates for MITRE ATT&CK Navigator in Python Dictionary format.
'''

layer_template = {
	'name': 'layer',
	'versions': {
		'attack': '14',
		'navigator': '4.9.1',
		'layer': '4.5'
	},
	'domain': 'enterprise-attack',
	'description': '',
	'showTacticRowBackground': True,
	'tacticRowBackground': '#7725c9',
	'techniques': []
}

technique_template = {
    "techniqueID": "",
    "color": "",
    "comment": "",
    "metadata": [],
    "links": [],
    "enabled": True,
    "showSubtechniques": False
}
