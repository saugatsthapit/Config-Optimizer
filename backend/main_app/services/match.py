import json
import os

def read_json_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return None

def find_matched_rules(directory, rule_criteria, exclude_rule_name=None):
    matched_rules = []
    if not rule_criteria:
        return matched_rules

    for filename in os.listdir(directory):
        if filename.endswith('.json'):
            file_path = os.path.join(directory, filename)
            data = read_json_file(file_path)
            if data is not None:
                def check_rule(rule, parent_name=''):
                    if 'name' in rule and rule.get('criteria', []) == rule_criteria and rule['name'] != exclude_rule_name:
                        matched_name = f"Parent: {rule['name']}" if not parent_name else f"- Child of {parent_name}: {rule['name']}"
                        matched_rules.append(matched_name)
                    for child in rule.get('children', []):
                        check_rule(child, rule.get('name', 'Unknown'))

                check_rule(data)
    return matched_rules

def search(directory):
    results = []

    for filename in os.listdir(directory):
        if filename.endswith('.json'):
            file_path = os.path.join(directory, filename)
            data = read_json_file(file_path)
            if data is not None:
                def process_rule(rule, parent_name=''):
                    if 'name' in rule and rule.get('criteria', []):
                        rule_name = rule['name']
                        matched_rules = find_matched_rules(directory, rule.get('criteria', []), rule['name'])
                        for matched_rule in matched_rules:
                            results.append({
                                'triggered_rule': rule_name,
                                'matched_rule': matched_rule
                            })
                        for child in rule.get('children', []):
                            process_rule(child, rule_name)

                process_rule(data)
    
    return results