from functools import partial
import yaml
import os
import jsonschema
import json
import datetime
from mitre_mapping import technique_to_name, tactic_to_name, technique_full_id, technique_tactic_allowed
from dotmap import DotMap
import re
import requests

json_schema_path = os.path.join(os.path.dirname(__file__),"..","docs","schemas","usecase_schema.json")
json_schema = json.load(open(json_schema_path, encoding='utf8'))
json_validator = jsonschema.Draft7Validator(json_schema)

table_names = json_schema['properties']['data_sources']['items']['properties']['table_name']['enum']
table_regexps = {
    t: re.compile(r'\b' + t + r'\b') for t in table_names
}

# Regex modified from https://stackoverflow.com/questions/7160737/how-to-validate-a-url-in-python-malformed-or-not
url_regex = re.compile(
        r'^(?:http)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

timeframe_regex = re.compile(r"^\s*let timeframe\s?=\s?{{\s?timeframe\s?\|\s?default\('\d+[hds]'\)\s?}};", re.MULTILINE)

class ValidationError(Exception):
    def __init__(self, message):
        self.message = message

def valid_version(v):
    s = v.split('.')
    if len(s) != 2:
        return False
    return all(map(lambda x: x.isnumeric(), s))

def parse_version(v):
    return list(map(int, v.split('.')))

def parse_date(d):
    return datetime.datetime.strptime(d, "%Y-%m-%d")

def valid_date(d):
    try:
        parse_date(d)
    except:
        return False
    return True

class Usecase(object):
    def __init__(self, data):
        self.data = DotMap(data, _dynamic=False)
        self.testcases = []
        self.raw_yaml = ''
        self.fn = None
        self.sop = None
        self.notes = {}
        self.cp = None

    def add_testcase(self, testcase):
        if any(map(lambda x: x.data.id == testcase.data.id, self.testcases)):
            return
        self.testcases.append(testcase)

    def add_sop(self, sop):
        self.sop = sop

    def __str__(self):
        return f'Usecase:<{self.data.id}>'

    # Validate use-case data based on json schema
    # Throws an error in case of validation error
    def schema_validate(self):
        try:
            json_validator.validate(self.data.toDict())
        except jsonschema.exceptions.ValidationError as e:
            raise ValidationError(str(e.message))

    # Checks that the id in the usecase matches the path the usecase was loaded from
    def validate_path(self, path_name):
        path = os.path.basename(path_name)
        if path != self.data.id:
            raise ValidationError(f"Path {path} does not match id {self.data.id}")

    def validate_changelog(self):
        prev_version = None
        prev_date = None
        # Process changelog in reverse order so that dates are old to new
        for cl in self.data.change_log[::-1]:
            if not valid_version(cl['version']):
                raise ValidationError(f"Version {cl['version']} is not valid")
            if prev_version != None and parse_version(cl['version']) <= prev_version:
                raise ValidationError(f"Version {cl['version']} is not larger than previous version {prev_version} - Note newest changes should be on top")
            if not valid_date(cl['date']):
                raise ValidationError(f"Date {cl['date']} is not valid, should bear YYYY-MM-DD")
            if prev_date != None and parse_date(cl['date']) < prev_date:
                raise ValidationError(f"Date {cl['date']} is not larger or equal than previous date - Note newest changes should be on top")
            prev_version = parse_version(cl['version'])
            prev_date = parse_date(cl['date'])

    def validate_references(self):
        for ref in self.data.references:
            if not(url_regex.match(ref)):
                raise ValidationError(f"Reference {ref} is not a valid URL, use only URLs as references")

    def validate_mitre(self):
        unique_seen = {}
        for technique in self.data.attack:
            try:
                tech = technique.technique
                sub_tech = technique.get('sub_technique', None)
                tech_name = technique_full_id(tech, sub_tech)
                technique_to_name(tech, sub_tech)
                tactic = technique['tactic']
            except:
                raise ValidationError(f"Unknown MITRE technique: {tech_name}")

            uniq_id = f'{tactic}-{tech_name}'
            if uniq_id in unique_seen:
                raise ValidationError(f'Duplicate technique with same tactic: {uniq_id}')
            unique_seen[uniq_id] = True

            try:
                tactic_to_name(tactic)
            except:
                raise ValidationError(f"Unknown MITRE tactic: {tactic}")

            if not technique_tactic_allowed(tactic, tech_name):
                raise ValidationError(f"Combination of technique {tech_name} and tactic {tactic} is not allowed")

    def validate_m365_entity_mapping(self, query):
        allowed_mappings = {
            'machine': ['DeviceId', 'DeviceName', 'RemoteDeviceName'],
            'user': ['AccountObjectId', 'AccountSid', 'AccountUpn', 'InitiatingProcessAccountObjectId', 'InitiatingProcessAccountSid', 'InitiatingProcessAccountUpn', 'RequestAccountSid', 'RecipientObjectId'],
            'mailbox': ['RecipientEmailAddress', 'SenderFromAddress', 'SenderMailFromAddress']
        }
        for k,v in query.deployment_variables.entity_mapping.items():
            if not k in allowed_mappings:
                raise ValidationError(f"Unknown entity type {k}")
            if not v in allowed_mappings[k]:
                raise ValidationError(f"Entity mapping '{k}: {v}' is not supported in M365. The only mappings allowed for {k} are {allowed_mappings[k]}")

    # Validate query specific data
    def validate_queries(self):
        query = self.data.detection_query
        # Sentinel specific checks
        if query.platform == "Sentinel":
            if not 'deployment_variables' in query:
                raise ValidationError("deployment_variables is a mandatory attribute for Sentinel query")
            if 'DedupFields' in query.query:
                if not 'custom_details' in query.deployment_variables or not 'DedupEntity' in query.deployment_variables.custom_details:
                    raise ValidationError("custom_details.DedupEntity is a mandatory attribute for queries that use Sentinel dedup logic")
            if not 'query_frequency' in query.deployment_variables:
                raise ValidationError("query_frequency is a mandatory attribute for Sentinel query")
            if 'query_period' in query.deployment_variables:
                m = re.match(r'P(\d+)D', query.deployment_variables.query_period)
                if m and int(m.groups(1)[0]) > 14:
                    raise ValidationError("query_period should be at most 14 days")
        if query.platform == "M365 Security":
            if not 'deployment_variables' in query:
                raise ValidationError("deployment_variables is a mandatory attribute for M365 Security query")
            if not 'query_frequency' in query.deployment_variables:
                raise ValidationError("query_frequency is a mandatory attribute for M365 Security query")
            valid_periods = ['PT1H', 'PT3H', 'PT12H', 'PT24H', 'P1D']
            if not query.deployment_variables.query_frequency in valid_periods:
                raise ValidationError(f"query_frequency has to be one of {','.join(valid_periods)}")
            if 'query_period' in query.deployment_variables:
                raise ValidationError("query_period is not allowed for M365 Security query")
            if not 'entity_mapping' in query.deployment_variables:
                raise ValidationError("entity_mapping is a mandatory attribute for M365 Security query")
            self.validate_m365_entity_mapping(query)

    def validate_forbidden_words(self, client_forbidden_words=[]):
        warnings = []
        global_exclude_words = ['TODO', 'tbd']
        global_exclude_words.extend(client_forbidden_words)
        data_str = str(self.raw_yaml).lower()
        for word in global_exclude_words:
            if word.lower() in data_str:
                warnings.append(f"Usecase contains string '{word}'")
        return warnings

    def validate_timeframe_usage(self):
        warnings = []
        timeframe_usage= '| where ingestion_time() >= ago(timeframe)'
        if not timeframe_usage in self.data.detection_query.query:
            warnings.append(f"Query does not use the expected timeframe usage: {timeframe_usage}")
        return warnings

    def validate_global_prevalence(self):
        warnings = []
        query = self.data.detection_query
        if 'GlobalPrevalence' in query.query and not 'coalesce' in query.query:
            warnings.append("Query uses GlobalPrevalence without coalesce - recommend to use coalesce(GlobalPrevalence,0)")
        return warnings

    def validate_file_profile_argument(self):
        warnings = []
        query = self.data.detection_query
        if re.search(r'FileProfile\s*\([^,]*\)', query.query):
            warnings.append("Query uses FileProfile without a second argument indicating the number of items to lookup.")
        match = re.search(r'FileProfile\s*\([^,]*,\s*(\d+)\s*\)', query.query)
        if match and match.group(1) != '1000':
            warnings.append(f"Query uses FileProfile with a second argument {match.group(1)} other than 1000.")
        return warnings

    def validate_entity_mapping(self):
        warnings = []
        query = self.data.detection_query
        if not 'entity_mapping' in query.deployment_variables:
            warnings.append("Query does not specify an entity_mapping")
        return warnings

    def validate_unused_table(self):
        warnings = []
        specified_tables = [d.table_name for d in self.data.data_sources if 'table_name' in d]
        query = self.data.detection_query
        for table_name, table_regex in table_regexps.items():
            if table_regex.search(query.query):
                continue
            if table_name in specified_tables:
                warnings.append(f"Query does not use {table_name} but this table is listed in data_sources.")
        return warnings

    def validate_unspecified_table(self):
        warnings = []
        specified_tables = [d.table_name for d in self.data.data_sources if 'table_name' in d]
        query = self.data.detection_query
        for table_name, table_regex in table_regexps.items():
            if table_name in specified_tables:
                continue
            if table_regex.search(query.query):
                warnings.append(f"Query appears to use table {table_name} but this table is not listed in data_sources.")
        return warnings

    def validate_shared_tables(self):
        warnings = []
        shared_tables = [
            'CloudAppEvents',
            'CommonSecurityLog',
            'OfficeActivity',
            'AzureDiagnostics'
        ]
        table_has_data_availability_test = {}
        reported_tables = {}

        # Check if there is a shared table used where none of the instances
        # of this shared table mention a data_availability_test
        for data_source in self.data.get('data_sources',[]):
            if not data_source.get('table_name', '') in shared_tables:
                continue
            if data_source.get('data_availability_test'):
                table_has_data_availability_test[data_source.table_name] = True

        for data_source in self.data.get('data_sources',[]):
            if not data_source.get('table_name', '') in shared_tables:
                continue
            if data_source.table_name in reported_tables:
                continue
            if table_has_data_availability_test.get(data_source.table_name):
                continue
            warnings.append(f"Query uses a shared table: {data_source.table_name} without a data_availability_test")
            reported_tables[data_source.table_name] = True
        return warnings


    def validate_query_empty_lines(self):
        warnings = []
        query = self.data.detection_query
        if re.search(r'^\s*$', query.query.rstrip(), re.MULTILINE):
            warnings.append("Query contains blank lines inside query.")
        return warnings

    def is_warning_skipped(self, warning):
        for silenced in self.data.get('silence_warnings', []):
            if silenced.warning == warning:
                return True
        return False

    def validate_warnings(self, client_forbidden_words=[]):
        validators = {
            'W_FORBIDDEN_WORDS': partial(self.validate_forbidden_words, client_forbidden_words),
            'W_TIMEFRAME_USAGE': self.validate_timeframe_usage,
            'W_GLOBAL_PREVALENCE': self.validate_global_prevalence,
            'W_FILEPROFILE_SINGLE_ARGUMENT': self.validate_file_profile_argument,
            'W_ENTITY_MAPPING': self.validate_entity_mapping,
            'W_UNSPECIFIED_TABLE_USED': self.validate_unspecified_table,
            'W_UNUSED_TABLE': self.validate_unused_table,
            'W_SHARED_TABLE_WITHOUT_DATA_AVAILABILITY_TEST': self.validate_shared_tables,
            'W_QUERY_EMPTY_LINES': self.validate_query_empty_lines,
        }
        warnings = []

        for (warning_name, warning_function) in validators.items():
            if self.is_warning_skipped(warning_name):
                continue
            new_warnings_prefixed = [f'{warning_name}: {s}' for s in warning_function()]
            warnings.extend(new_warnings_prefixed)
        return warnings

    # Perform in-depth validation of use-case
    # Throws an error in case of validation error
    def validate(self):
        self.schema_validate()
        self.validate_mitre()
        self.validate_changelog()
        self.validate_queries()
        self.validate_references()

    def validate_query_syntax(self, query, language_server, client):
        warnings = []
        platform_names = {
            'Sentinel': 'sentinel',
            'M365 Security': 'm365'
        }
        platform = platform_names.get(query.platform, None)
        if not platform:
            raise Exception(f"Unknown platform {query.platform}")

        if client:
            # toDict is needed below because otherwise the json serializer of requests will serialize the DotMap as an empty
            # dictionary, which will cause the language server to fail.
            local_data = {
                'tabular_functions': client.data.get('query_validation',{}).get('tabular_functions',DotMap({})).toDict(),
                'scalar_functions': client.data.get('query_validation',{}).get('scalar_functions',DotMap({})).toDict(),
                'watchlists': client.data.get('query_validation',{}).get('watchlists',DotMap({})).toDict(),
                'tables': client.data.get('query_validation',{}).get('tables',DotMap({})).toDict(),
            }
        else:
            local_data = {}

        request = {'query': query.query, 'environment': platform, 'local_data': local_data }
        r = requests.post(language_server, json=request)
        if r.status_code != 200:
            raise Exception(f"[E] Error analyzing query using language server: HTTP Status code {r.status_code} - {r.text}")

        if r.json().get('parsing_errors'):
            warnings.append(f"Query contains Syntax errors: {r.json().get('parsing_errors')}")

        # Check entity mappings and custom details occur in the query result set.
        if platform == 'sentinel':
            required_output_columns = []
            for entity_mapping in query.deployment_variables.get('entity_mapping', []):
                for ev in entity_mapping.values():
                    required_output_columns.extend(ev.values())
            required_output_columns.extend(query.deployment_variables.get('custom_details', {}).values())
        else:
            required_output_columns = list(query.deployment_variables.get('entity_mapping', {}).values())

        output_columns = r.json().get('output_columns', {})

        for column in required_output_columns:
            if not column in output_columns:
                warnings.append(f"Query uses entity mapping/custom details column '{column}' which is not in the query result set.")

        # Check ReportId, Timestamp and DeviceId are present in the output
        # for M365 use-cases
        if platform == 'm365':
            # DeviceId is not required in case any of the following tables are used.
            tables_without_deviceid = ['IdentityQueryEvents', 'UrlClickEvents']
            for column in ['ReportId', 'Timestamp', 'DeviceId']:
                if column == 'DeviceId' and any(c in r.json().get('referenced_tables', []) for c in tables_without_deviceid):
                    continue
                if not column in output_columns:
                    warnings.append(f"Query does not contain mandatory M365 column: {column} in the output.")
        return warnings

    # Return all unique tactics
    @property
    def tactics(self):
        r = []
        for technique in self.data.attack:
            if not technique.get('tactic') in r:
                r.append(technique.get('tactic'))
        return r

    @property
    def platform(self):
        return self.data.detection_query.platform

    @classmethod
    def load_from_file(cls, file_name, check_path_consistency=True):
        raw_yaml = open(file_name, encoding='utf8').read()
        yaml_loader = yaml.CSafeLoader if hasattr(yaml, 'CSafeLoader') else yaml.SafeLoader
        data = yaml.load(raw_yaml, Loader=yaml_loader)
        uc = cls(data)
        uc.raw_yaml = raw_yaml
        uc.fn = file_name
        uc.validate()
        if check_path_consistency:
            uc.validate_path(os.path.dirname(file_name))
        return uc
