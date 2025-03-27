#!/usr/bin/env python3

script_version = "1.4.1"

print("""
#################################################################
#                                                               #
#     ▄▀█ █░█ █▀▄ █ ▀█▀                                        #
#     █▀█ █▄█ █▄▀ █ ░█░                                        #
#                                                               #
#                    ▀█                                         #
#                    █▄                                         #
#                                                               #
#     █▀▀ █░░ ▄▀█ █▀ ▀█▀ █ █▀▀ █▀ █▀▀ ▄▀█ █▀█ █▀▀ █░█         #
#     ██▄ █▄▄ █▀█ ▄█ ░█░ █ █▄▄ ▄█ ██▄ █▀█ █▀▄ █▄▄ █▀█         #
#                                                               #
#                      Version: {0}                             #
#                                                               #
#################################################################
""".format(script_version))

from argparse import ArgumentParser, REMAINDER
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk, parallel_bulk
from elasticsearch.helpers.errors import BulkIndexError
from dateutil.tz import gettz
import urllib3
import warnings

import sys, os, csv, json, re, dateutil.parser, pprint

# Suppress insecure request warnings when verify_certs is False
warnings.filterwarnings("ignore", category=UserWarning, module="elasticsearch.connection")
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

parser = ArgumentParser(prog='audit2elastic', description='Push Office 365 audit logs to ElasticSearch')

parser.add_argument('--server', '-s', dest='elastic_server', action='store', default=os.environ.get('ES_HOSTS', 'http://127.0.0.1:9200'), help='ElasticSearch server(s)')
parser.add_argument('--index',  '-i', dest='elastic_index',  action='store', default='o365-%s' % hex(abs(hash(json.dumps(sys.argv[1:]))))[2:10], help='ElasticSearch index name')
parser.add_argument('--api-key', '-k', dest='api_key', action='store', help='ElasticSearch API key for authentication')
parser.add_argument('--ignore-ssl', dest='ignore_ssl', action='store_true', help='Ignore SSL certificate verification (use with caution)')
parser.add_argument('--skip-test', dest='skip_test', action='store_true', help='Skip Elasticsearch connection test')
parser.add_argument('--timeout', '-t', dest='timeout', action='store', type=int, default=60, help='Elasticsearch operation timeout in seconds (default: 60)')
parser.add_argument('--continue-on-error', dest='continue_on_error', action='store_true', help='Continue processing even if some documents fail to index')
parser.add_argument('--append', '-a', dest='append_mode', action='store_true', help='Append to existing index (required if index already exists)')
parser.add_argument("paths", nargs=REMAINDER, help='Target audit log file(s)', metavar='paths')

args, extra = parser.parse_known_args(sys.argv[1:])

# Check if source files are specified
if not args.paths:
    print("Error: No source files specified.")
    print()
    parser.print_help()
    sys.exit(1)

# Initialize Elasticsearch client with appropriate options
if args.api_key:
    es = Elasticsearch(args.elastic_server, api_key=args.api_key, verify_certs=not args.ignore_ssl, 
                      timeout=args.timeout, index=args.elastic_index)
else:
    es = Elasticsearch(args.elastic_server, verify_certs=not args.ignore_ssl, 
                      timeout=args.timeout, index=args.elastic_index)
tzinfos = {"AEST" : gettz("Australia/Brisbane")}

print(f"Using server: {args.elastic_server}")
print(f"Using index: {args.elastic_index}")
print(f"Using timeout: {args.timeout} seconds")
if args.api_key:
    print("Using API key authentication")
if args.continue_on_error:
    print("Will continue processing despite indexing errors")
if args.append_mode:
    print("Append mode enabled (will add to existing index if it exists)")

# Test Elasticsearch connection and authentication if not skipped
if not args.skip_test:
    print("Testing connection to Elasticsearch...")
    try:
        info = es.info()
        print(f"Successfully connected to Elasticsearch cluster: {info.get('cluster_name', 'unknown')}")
    except Exception as e:
        print(f"ERROR: Failed to connect to Elasticsearch: {str(e)}")
        print("Please check your server URL, API key, and network connectivity.")
        print("You can use --skip-test to bypass this check if you're sure your configuration is correct.")
        sys.exit(1)

# Check if index already exists
print(f"Checking if index '{args.elastic_index}' exists...")
try:
    if es.indices.exists(index=args.elastic_index):
        print(f"Index '{args.elastic_index}' already exists.")
        if not args.append_mode:
            print("ERROR: Index already exists and append mode is not enabled.")
            print("Use --append flag to append to an existing index.")
            sys.exit(1)
        print("Append mode enabled. Will add documents to existing index.")
    else:
        print(f"Index '{args.elastic_index}' does not exist. Will create new index.")
except Exception as e:
    print(f"WARNING: Failed to check if index exists: {str(e)}")
    print("Will attempt to proceed anyway.")

def convert_key(string):
    # Remove leading underscore if present
    if string.startswith('_'):
        string = string[1:]
        
    # Return the string with minimal changes, preserving CamelCase
    return string.replace(' ', '')

def normalise_user(string):
    return re.sub(r'(.*\\)?([^@ ]+)([@ ].*)?', r'\2', string.lower())

def parse_date(string, fuzzy=True):
    return dateutil.parser.parse(string)

def parse_audit_data(string, parent_field=None):
    if not type(string) in (bytes, str): return string
    if not str(string).startswith(('"', "'", "{", "[")): return string
    try:
        audit_data = json.loads(string, object_pairs_hook=object_pairs_hook(parent_field))
        if type(audit_data) is dict: flattened = flatten_audit_data(audit_data)
        else: flattened = audit_data
        return flattened
    except json.JSONDecodeError as ex:
        return string

def object_pairs_hook(parent_field=None):
    def wrapper(pairs):
        obj = {}
        for key, value in pairs:
            # Create a context-aware key name with dot notation
            context_key = f"{parent_field}.{convert_key(key)}" if parent_field else convert_key(key)
            obj[context_key] = value
            
        # Handle special cases for Name/Value pairs
        if set(obj.keys()) == {'Name', 'Value'} or set(obj.keys()) == {'name', 'value'}:
            name_key = 'Name' if 'Name' in obj else 'name'
            value_key = 'Value' if 'Value' in obj else 'value'
            value = parse_audit_data(obj[value_key])
            return {convert_key(obj[name_key]): value}
        elif set(obj.keys()) == {'Name', 'NewValue', 'OldValue'} or set(obj.keys()) == {'name', 'new_value', 'old_value'}:
            name_key = 'Name' if 'Name' in obj else 'name'
            new_value_key = 'NewValue' if 'NewValue' in obj else 'new_value'
            value = parse_audit_data(obj[new_value_key], parent_field)
            return {convert_key(obj[name_key]): value}
        if set(obj.keys()) == {'ID', 'Type'} or set(obj.keys()) == {'id', 'type'}:
            return obj
        return obj
    return wrapper

def flatten(item, key=None):
    flattened = {}
    if isinstance(item, dict): flattened.update(flatten_dict(item, prefix=key))
    elif isinstance(item, list): flattened.update(flatten_list(item, prefix=key))
    else: flattened[key] = item
    return flattened

def flatten_dict(data, prefix=None):
    flattened = {}
    for key, value in data.items():
        # Use dot notation for nested fields
        nested_key = f"{prefix}.{key}" if prefix else key
        flattened.update(flatten(value, nested_key))
    return flattened

def flatten_list(items, prefix=None):
    flattened = {}
    flattened_items = {}
    for item in items:
        flattened_item = flatten(item, prefix)
        for key, value in flattened_item.items():
            flattened_items.update({key: [value]}) if key not in flattened_items.keys() else flattened_items[key].append(value)
    flattened.update(flattened_items)
    return flattened

def flatten_audit_data(audit_data, prefix=''):
    if type(audit_data) is dict:
        return flatten(audit_data)
    return audit_data

def convert_field_types(record):
    """
    Convert field types to match Elasticsearch expectations.
    Handles known problematic fields and performs type conversions.
    """
    # Create a new record with renamed keys (removing leading underscores)
    renamed_record = {}
    for key, value in record.items():
        if key.startswith('_'):
            renamed_record[key[1:]] = value
        else:
            renamed_record[key] = value
    record = renamed_record
    
    # Fix double-nested field names (e.g., AuditData.AuditData.Field -> AuditData.Field)
    fixed_record = {}
    for key, value in record.items():
        # Check for patterns like "AuditData.AuditData.Field"
        if '.' in key:
            parts = key.split('.')
            if len(parts) >= 3 and parts[0] == parts[1]:
                # Remove the duplicate prefix
                new_key = '.'.join([parts[0]] + parts[2:])
                fixed_record[new_key] = value
            else:
                fixed_record[key] = value
        else:
            fixed_record[key] = value
    
    record = fixed_record
    
    # Handle ModifiedProperties field - convert array to object if needed
    modified_props_fields = [field for field in record.keys() 
                           if field.endswith('ModifiedProperties') and isinstance(record[field], list)]
    for field_name in modified_props_fields:
        # Convert the array to an object with properties as keys
        modified_props = {}
        for prop in record[field_name]:
            if isinstance(prop, str):
                modified_props[prop] = True
            elif isinstance(prop, dict):
                for k, v in prop.items():
                    modified_props[k] = v
        record[field_name] = modified_props
    
    # Handle any other array fields that might cause issues
    for key, value in record.items():
        if isinstance(value, list) and key.endswith('Properties'):
            # Convert arrays to objects for fields ending with "Properties"
            props_obj = {}
            for item in value:
                if isinstance(item, str):
                    props_obj[item] = True
                elif isinstance(item, dict):
                    for k, v in item.items():
                        props_obj[k] = v
            record[key] = props_obj
    
    # Handle Parameters field - convert command-line parameter string to object
    for param_field in ['Parameters', 'NonPIIParameters']:
        if param_field in record and isinstance(record[param_field], str):
            # Parse command-line parameters into an object
            params_obj = {}
            # Simple regex to extract parameter names and values
            param_pattern = r'-(\w+)\s+"([^"]*)"'
            matches = re.findall(param_pattern, record[param_field])
            for param_name, param_value in matches:
                params_obj[param_name] = param_value
            
            # If we successfully parsed parameters, replace the string with the object
            if params_obj:
                record[param_field] = params_obj
            else:
                # If parsing failed, remove the field to prevent mapping conflicts
                del record[param_field]
    
    # Handle numeric fields that Elasticsearch expects to be integers
    numeric_field_suffixes = ['ListBaseType', 'ListBaseTemplateType', 'RecordType', 'ItemCount']
    for suffix in numeric_field_suffixes:
        # Find all fields ending with this suffix (with or without prefix)
        matching_fields = [field for field in record.keys() 
                          if field.endswith(suffix)]
        
        for field_name in matching_fields:
            try:
                if isinstance(record[field_name], str):
                    if record[field_name].isdigit():
                        record[field_name] = int(record[field_name])
                    else:
                        # Non-numeric string that can't be converted - remove it
                        del record[field_name]
            except (ValueError, TypeError):
                # If conversion fails, remove the field
                del record[field_name]
    
    return record

def process_records(path):
    with open(path) as audit_file:
        lines = len(audit_file.readlines()) - 1
        audit_file.seek(0)
        audit_csv = csv.reader(audit_file)
        header = next(audit_csv)
        keys = [convert_key(key) for key in header]
        for i, values in enumerate(audit_csv, 1):
            # Special handling for AuditData column to avoid double nesting
            record = {}
            for key, value in zip(keys, values):
                # For AuditData column, parse the JSON without adding the parent field prefix
                if key == 'AuditData':
                    parsed_data = parse_audit_data(value)
                    if isinstance(parsed_data, dict):
                        # Only add AuditData prefix if the field would conflict with an existing field
                        for k, v in parsed_data.items():
                            if k in record:  # Field name already exists in the record
                                record[f"AuditData.{k}"] = v  # Add prefix to avoid collision
                            else:
                                record[k] = v  # No prefix needed
                    else:
                        record[key] = parsed_data
                else:
                    record[key] = parse_audit_data(value)
            record['username'] = None
            for key, value in record.copy().items():
                if value in (None, 'null', '<null>', [], ['<null>'], [''], '', [['']], {}) and key != 'username':
                    del record[key]
                elif value and key in ('SenderIp', 'ClientIpAddress', 'ClientIp', 'ActorIpAddress', 'FromIp', 'sender_ip', 'client_ip_address', 'client_ip', 'actor_ip_address', 'from_ip') and 'IpAddress' not in record.keys():
                    record['IpAddress'] = re.sub(r'\[?((([1-9]+[0-9]*\.){3,}[1-9]+[0-9]*)|((([1-9a-f]+[0-9a-f]*)?:){1,8}[0-9a-f]*[1-9a-f]+))\]?.*', r'\1', value)
                elif key in ('CreationTime', 'EndDate', 'creation_time', 'end_date') and 'Timestamp' not in record.keys():
                    record['Timestamp'] = parse_date(value)
                    # del record[key]
                elif key in ('CreationDate', 'RunDate', 'LastAccessed', 'creation_date', 'run_date', 'last_accessed') and 'Timestamp' not in record.keys():
                    timeentry=value+" AEST"
                    record['Timestamp'] = dateutil.parser.parse(timeentry, dayfirst=True, fuzzy=True, tzinfos=tzinfos)
                elif key in ('Username', 'MailboxOwnerUPN', 'username', 'mailbox_owner_upn') and value is not None:
                    record['username'] = normalise_user(value)
                elif key in ('ItemIsRecord', 'UserType', 'InternalLogonType', 'AzureActiveDirectoryEventType', 'CrossMailboxOperation', 'LogonType', 'ExternalAccess', 'item_is_record', 'user_type', 'internal_logon_type', 'azure_active_directory_event_type', 'cross_mailbox_operation', 'logon_type', 'external_access'):
                    record[key] = str(value)
                elif key in ('', None, 'null'):
                    record['ExtendedProperties'] = value
                    del record[key]
            if i % 1000 == 0 or i == lines: print(f"Processed {i}/{lines} records")
            # pprint.pprint(record)
            yield record



for path in args.paths:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Audit log file {path} not found")
    print(f"Processing {path}...")
    try:
        for ok, info in parallel_bulk(
            es, 
            ({"_index": args.elastic_index, "_id": hex(abs(hash(json.dumps(record, sort_keys=True, default=str)))), "_source": convert_field_types(record)} for record in process_records(path)),
            chunk_size=500,  # Process in smaller chunks
            max_chunk_bytes=10485760,  # 10MB max chunk size
            request_timeout=args.timeout
        ):
            if not ok: print(f"Error {info}")
    except BulkIndexError as e:
        print(f"Bulk indexing error: {str(e)}")
        print(f"Failed documents: {len(e.errors)}")
        if not args.continue_on_error:
            print("Use --continue-on-error to continue processing despite indexing errors")
            sys.exit(1)
        print("Continuing with next file due to --continue-on-error flag")
