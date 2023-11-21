#!/usr/bin/env python3

'''
Connects to Chronicle SIEM and retrieves some useful rule metadata.

REQUIRES
- A valid key file with enough permissions to access rules in SIEM.
- Google API Client: pip install google-api-python-client
- Rules in Chronicle SIEM with these fields in the `meta` section:
    - mitre_datasource = "DS0000"
    - mitre_technique  = "T0000, T0001"

'''


from urllib.parse import urlencode
from http import HTTPStatus
from json import loads
from csv import writer
from copy import deepcopy

from google.oauth2 import service_account
from google.auth.transport.requests import AuthorizedSession
from googleapiclient import _auth

from sextant.navigator import technique_template


def init_webclient(keyfile, region="North America"):
    #@param ['North America', 'Europe', 'Asia (Singapore)', 'United Kingdom', 'Australia (Sydney)', 'Tel Aviv']

    SCOPES = [
        'https://www.googleapis.com/auth/chronicle-backstory',  # regular backstory API
        'https://www.googleapis.com/auth/malachite-ingestion',  # ingestion API
        'https://www.googleapis.com/auth/cloud-platform'        # dataplane API (experimenting)
    ]

    if region == 'North America':
        region_prefix = ''
        cbn_region = 'US'
        cli_region = 'US'
    elif region == 'Europe':
        region_prefix = 'europe-'
        cbn_region = 'EUROPE'
        cli_region = 'EUROPE'
    elif region == 'United Kingdom':
        region_prefix = 'europe-west2-'
        # won't work because the CBN tool doesn't have the UK region in it
        cbn_region = 'EUROPE'    
        cli_region = 'EUROPE-WEST2'
    elif region == 'Asia (Singapore)':
        region_prefix = 'asia-southeast1-'
        cbn_region = 'ASIA'
        cli_region = 'ASIA-SOUTHEAST1'
    elif region == 'Australia (Sydney)':
        region_prefix = 'australia-southeast1-'
        cbn_region = 'AUSTRALIA'
        cli_region = 'AUSTRALIA-SOUTHEAST1'
    elif region == 'Tel Aviv':
        region_prefix = 'me-west1-'
        cbn_region = 'AUSTRALIA'
        cli_region = 'ME-WEST1'

    credentials = service_account.Credentials.from_service_account_file(keyfile, scopes=SCOPES)
    http_client = _auth.authorized_http(credentials)
    session = AuthorizedSession(credentials)
    return (http_client, session, region_prefix, cbn_region, cli_region)

def request(http_client, region_prefix, page_size=2000, page_token=''):
    'page_size (int), page_token (str)'
    url_params = {'page_size': page_size}
    if page_token:
        url_params['page_token'] = page_token

    uri = f'https://{region_prefix}backstory.googleapis.com/v2/detect/rules?{urlencode(url_params)}'
    res = http_client.request(uri, 'GET')

    if res[0].status == HTTPStatus.OK:
        return loads(res[1])
    else:
        return loads(res[1]).get('error').get('message')

def get_techniques(keyfile, color, comment):
    http_client, session, region_prefix, cbn_region, cli_region = init_webclient(keyfile)
    res = request(http_client, region_prefix)
    techniques = dict()
    templated = list()

    for rule in res['rules']:
        try:
            rule_techniques = set([x.strip() for x in rule['metadata']['mitre_technique'].split(',')])
        except KeyError:
            print(f'{rule["ruleName"]} is missing the meta/mitre_technique field')

        # TODO: check if the technique id is following the patern /T\d+\.\d+/

        for t in rule_techniques:
            if t not in techniques:
                techniques[t] = {
                    'metadata': [{'name':'rule','value':rule['ruleName']}],
                    'links': [{'label':'reference','url':rule['metadata']['reference']}]
                }
            else:
                techniques[t]['metadata'].append({'name':'rule','value':rule['ruleName']})
                techniques[t]['links'].append({'label':'reference','url':rule['metadata']['reference']})
        
    for k,v in techniques.items():
        tt = deepcopy(technique_template)
        tt['techniqueID'] = k
        tt['color'] = color
        tt['comment'] = comment
        tt['metadata'] = v['metadata']
        tt['links'] = v['links']
        templated.append(tt)
    return templated


###
# Additional code, not used to date.
#
def get_rules_csv(keyfile):
    'WIP'
    http_client, session, region_prefix, cbn_region, cli_region = init_webclient(keyfile)
    res = request(http_client, region_prefix)
    parsed_rules = list()
    header = ['rule_id', 'rule_name', 'rule_description', 'rule_severity', 'rule_priority', 'rule_mitre_datasource', 'rule_mitre_technique', 'rule_reference', 'rule_response', 'rule_type', 'rule_creation_time']
    
    for rule in res['rules']:
    # must implement a verification for missing fields
        parsed_rules.append([
            rule['ruleId'],
            rule['ruleName'],
            rule['metadata']['description'],
            rule['metadata']['severity'],
            rule['metadata']['priority'],
            rule['metadata']['mitre_datasource'],
            rule['metadata']['mitre_technique'],
            # rule['metadata']['reference'],
            rule['metadata']['response'],
            rule['metadata']['status'],
            rule['ruleType'],
            rule['versionCreateTime']
        ])
    
    with open('chronicle.csv', 'w') as f:
        write = writer(f)
        write.writerow(header)
        write.writerows(parsed_rules)
