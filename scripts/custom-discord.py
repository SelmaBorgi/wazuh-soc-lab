#!/usr/bin/env python3

import sys
import json
import requests

# Arguments passés par Wazuh :
# <fichier alerte> <api_key> <hook_url>

alert_file = sys.argv[1]
hook_url = sys.argv[3]

ACTIONS = {
    '5712': 'IP BLOCKED (firewall-drop, 300 s)',
    '87105': 'FILE QUARANTINE TRIGGERED',
}

def color(level):
    if level >= 12:
        return 0xE74C3C
    if level >= 8:
        return 0xE67E22
    return 0x3498DB

def add(fields, name, value, inline=False):
    if value:
        fields.append({
            'name': name,
            'value': str(value)[:1000],
            'inline': inline
        })

with open(alert_file) as f:
    alert = json.load(f)

rule = alert.get('rule', {})
agent = alert.get('agent', {})
data = alert.get('data', {})
mitre = rule.get('mitre', {})

level = int(rule.get('level', 0))

fields = []

add(fields, 'Agent', agent.get('name'), True)
add(fields, 'Severity', level, True)
add(fields, 'Rule ID', rule.get('id'), True)
add(fields, 'Description', rule.get('description'))

add(fields, 'MITRE', ', '.join(mitre.get('id', [])))
add(fields, 'Tactic', ', '.join(mitre.get('tactic', [])))

add(fields, 'Agent IP', agent.get('ip'))
add(fields, 'Source IP', data.get('srcip'))

add(
    fields,
    'Detected File',
    data.get('virustotal', {}).get('source', {}).get('file')
)

add(
    fields,
    'Actions Taken',
    ACTIONS.get(str(rule.get('id')))
)

add(fields, 'Timestamp', alert.get('timestamp'))

payload = {
    'embeds': [{
        'title': 'Wazuh Alert',
        'color': color(level),
        'fields': fields
    }]
}

r = requests.post(
    hook_url,
    json=payload,
    timeout=10
)

sys.exit(0 if r.status_code in (200, 204) else 1)
