import json
import os
attack_mapping_fn = os.path.join(os.path.dirname(__file__),"attack_mapping.json")

attack_mapping = json.load(open(attack_mapping_fn, encoding='utf8'))
def technique_to_name(technique, sub_technique=None):
    tn = attack_mapping['techniques'][technique]
    if sub_technique:
        technique = technique_full_id(technique, sub_technique)
        tn = tn + ' - ' + attack_mapping['techniques'][technique]
    return tn

def technique_full_id(technique, sub_technique=None):
    if sub_technique:
        technique = f'{technique}.{sub_technique}'
    return technique

def technique_obj_full_id(t):
    if t.get('sub_technique'):
        return f'{t.technique}.{t.sub_technique}'
    return t.technique

def tactic_to_name(tactic):
    return attack_mapping['tactics'][tactic]

def tactic_to_full_name(tactic):
    return f'{tactic} - {tactic_to_name(tactic)}'

def technique_tactic_allowed(tactic,technique):
    allowed = attack_mapping['technique_tactic_mapping'].get(technique, [])
    return tactic in allowed

def technique_datasources(technique):
    return attack_mapping['technique_datasource_mapping'].get(technique, [])