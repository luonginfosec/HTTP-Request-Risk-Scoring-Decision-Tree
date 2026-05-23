# Scripts

Scripts are grouped by pipeline stage.

## `data_sources/`

Convert each source into the common request CSV schema:

```text
id,label,source,source_url,method,url,path,query_string,headers,body,raw_request,notes
```

Files:

```text
import_luongvd_positive.py
process_csic_dataset.py
process_malicious_zip.py
process_modsec_learn_dataset.py
process_normal_legitimate.py
process_owasp_modsec_logs.py
```

## `pipeline/`

Build the training dataset:

```text
merge_dataset.py
deduplicate_requests.py
extract_features.py
```

Default output:

```text
data/processed/features.csv
```

## `external_tests/`

Convert Burp XML exports for external model testing:

```text
process_qldt_burp_xml.py
process_burp_xml.py
```

These outputs are test data only. They are not merged into training unless you
explicitly pass them to `pipeline/merge_dataset.py`.
