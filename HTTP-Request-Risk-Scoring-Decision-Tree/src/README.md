# Source Code

Reusable code imported by scripts and notebooks.

```text
request_canonicalizer.py
```

Normalizes request fields before feature extraction:

```text
raw, lowercase, URL-decoded once, recursively decoded, HTML-decoded,
Unicode-normalized, normalized path, duplicate-preserving query params
```

```text
feature_extractor.py
```

Converts one request row into the manual feature columns used by the Decision
Tree model.

```text
burp_xml_converter.py
```

Converts Burp Suite XML exports into the common request CSV schema used by
`test_csv()` in the notebook.
