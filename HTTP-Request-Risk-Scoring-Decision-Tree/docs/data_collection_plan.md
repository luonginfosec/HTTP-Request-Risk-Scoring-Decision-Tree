# Data Collection Plan

## Target Dataset

Each row should represent one HTTP request.

Minimum schema:

```csv
id,label,source,source_url,method,url,path,query_string,headers,body,raw_request,notes
```

Labels:

```text
1 = suspicious / exploited / attack-shaped request
0 = ordinary valid request
```

For this project, we only need binary labels. The model will later output:

```text
risk_score = P(label=1) * 10
```

## Positive Samples

Use public, already-disclosed sources only. Do not test live third-party
systems.

Recommended sources:

1. Existing local dataset from `../luongvd/attack_requests.csv`
   - Already contains parsed request fields.
   - Label is always `1`.
   - Good first positive dataset.

2. Exploit-DB official GitLab mirror
   - Use the existing `../luongvd` collector if needed.
   - Good for PoC text containing raw HTTP requests, URLs, bodies, and headers.

3. Public bug bounty writeups
   - Use only disclosed reports/writeups.
   - Keep the evidence URL in `source_url`.

Quality rules for positives:

- Keep method, URL, query, headers, body, and raw request when available.
- Keep the public evidence link.
- Remove real secrets, cookies, and API tokens.
- Reject rows that are not actually HTTP requests.
- Avoid duplicate `(method, url, body)` rows.

## Normal Samples

Normal samples must not be too simple. If all normal requests are just
`GET /home`, the model will learn that every request with parameters is risky.

Recommended sources:

1. HTTP Archive
   - Use for large-scale normal web request metadata.
   - Filter for request URLs that look API-like or parameterized.
   - Good labels: `label=0`, `source=httparchive`.

2. OWASP crAPI local happy-path traffic
   - Run crAPI locally.
   - Use only normal user actions: register, login, view profile, add vehicle,
     search mechanics, create normal service request, read posts/comments.
   - Capture with browser DevTools, Burp, or OWASP ZAP.
   - Label these requests `0`.

3. OWASP Juice Shop local happy-path traffic
   - Run locally.
   - Use normal shopping actions: browse products, search, add to basket,
     login/register, checkout with normal values.
   - Capture only unmodified requests.
   - Label these requests `0`.

4. Common Crawl WARC request records
   - Optional source for ordinary crawler GET requests.
   - Useful if raw HTTP request shape is needed.
   - Lower priority because it is mostly unauthenticated GET traffic.

Quality rules for normal samples:

- Include diverse collected normal requests with `id`, `account_id`, `tenant`,
  `search`, `redirect`, `callback`, `/api/`, `/document`, upload/download-like
  names, and JSON bodies when they come from real normal traffic.
- Exclude static-only noise such as images, fonts, CSS, and most JS.
- Do not include attack payloads.
- Do not include modified IDs or bypass attempts.
- Remove real secrets, cookies, and tokens.

## First Collection Order

1. Copy local positive rows from `../luongvd/attack_requests.csv`.
2. Collect 2,000 to 5,000 normal rows from HTTP Archive.
3. Capture 300 to 1,000 normal API requests from local crAPI/Juice Shop usage.
4. Merge into one processed CSV with balanced labels for the first experiment.
5. Later, test on a more realistic imbalanced split.

Suggested first target:

```text
positive: 2,000 rows
normal:   2,000 rows
```

## Data Split Rule

Do not randomly split blindly if many rows come from the same source/report.

Use `source` or `source_url` as a split group when possible:

```text
same report/source group must not appear in both train and test
```

This reduces data leakage and overfitting.
