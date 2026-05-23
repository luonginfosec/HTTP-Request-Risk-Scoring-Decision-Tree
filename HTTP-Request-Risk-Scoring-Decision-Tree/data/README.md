# Data Layout

```text
raw/
  positive/     Attack or suspicious request CSVs
  normal/       Normal request CSVs
  owasp/        Original OWASP ModSecurity audit logs
external/       Downloaded third-party datasets
processed/      Merged datasets, deduplicated datasets, features, external test CSVs
reports/        Duplicate and leakage reports
```

Training file:

```text
processed/features.csv
```

External QLDT test file:

```text
processed/qldt_ptit_normal_requests.csv
```

Do not treat every CSV under `processed/` as training data. Only
`processed/features.csv` is used for model training by default.
