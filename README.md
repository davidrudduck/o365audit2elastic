# Microsoft 365 Audit to Elasticsearch

Python script to push the Microsoft 365 Unified Audit Log, Admin Audit Log and Mailbox Audit Logs into Elasticsearch. Works with the o365auditlogretriever scripts.

## Basic Usage

Run under WSL or with Python3 in Windows:
```bash
./audit2elastic.py --index o365-nameofcompany-ual /path/to/source/auditlog.csv
```

The index switch will need pre-pending o365-<nameofcompany> and append -ual 

`o365-` is there so that it goes into the correct enrichment pipeline.

`-ual` at the end is there so we can filter based on index and source (ual, mt)

## Command Line Arguments

```
--server, -s       ElasticSearch server(s) (default: http://127.0.0.1:9200)
--index, -i        ElasticSearch index name
--api-key, -k      ElasticSearch API key for authentication
--field-mapping, -m Path to field mapping JSON file for condensing fields
--ignore-ssl       Ignore SSL certificate verification (use with caution)
--skip-test        Skip Elasticsearch connection test
--timeout, -t      Elasticsearch operation timeout in seconds (default: 60)
--continue-on-error Continue processing even if some documents fail to index
--append, -a       Append to existing index (required if index already exists)
--debug            Enable debug output
```

## Field Mapping

To overcome the Elasticsearch 1,000 field limit, you can use a field mapping file to condense fields. This is particularly useful when processing large audit logs with many different field types.

```bash
./audit2elastic.py --index o365-nameofcompany-ual --field-mapping field_mapping_example.json /path/to/source/auditlog.csv
```

The field mapping file is a JSON file with the following structure:

```json
{
  "rename": {
    "OldField1": "NewField1",
    "OldField2": "NewField1"
  },
  "merge": {
    "TargetField1": ["SourceField1", "SourceField2"]
  },
  "ignore": [
    "FieldToIgnore1",
    "FieldToIgnore2"
  ],
  "conditional": [
    {
      "condition": {
        "field": "RecordType",
        "value": "ExchangeItem"
      },
      "rename": {
        "SpecificField1": "GenericField1"
      }
    }
  ]
}
```

See `field_mapping_example.json` for a more detailed example.

## Handling Elasticsearch Field Limit Errors

If you encounter the "Limit of total fields [1000] has been exceeded" error, you have several options:

1. Use the `--field-mapping` option with a mapping file to condense fields
2. Use the `--continue-on-error` flag to continue processing despite indexing errors
3. Increase the field limit in Elasticsearch:

```
PUT /your_index_name/_settings
{
  "index.mapping.total_fields.limit": 2000
}
```
