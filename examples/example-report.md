# LogHound Analysis

## Overview

File: `noisy-server.log`

| Metric | Value |
|---|---:|
| Lines scanned | 9 |
| Errors | 5 |
| Unique signatures | 4 |

## Most Frequent Failures

### request 9921 timed out after 5003ms

Occurrences: 2

First occurrence: Line 3

Severity: ERROR

Context:

```text
  1 2026-09-01 12:05:01 INFO server starting
  2 2026-09-01 12:05:02 INFO request 9919 completed HTTP 200
> 3 2026-09-01 12:05:03 ERROR request 9921 timed out after 5003ms
  4 2026-09-01 12:05:04 INFO retrying request 9921
  5 2026-09-01 12:05:05 ERROR request 9922 timed out after 5011ms
  6 2026-09-01 12:05:06 WARN slow query detected
  7 2026-09-01 12:05:07 CRITICAL database unavailable
  8 2026-09-01 12:05:08 ERROR HTTP 500 from /api/accounts/42
```

### database unavailable

Occurrences: 1

First occurrence: Line 7

Severity: CRITICAL

Context:

```text
  4 2026-09-01 12:05:04 INFO retrying request 9921
  5 2026-09-01 12:05:05 ERROR request 9922 timed out after 5011ms
  6 2026-09-01 12:05:06 WARN slow query detected
> 7 2026-09-01 12:05:07 CRITICAL database unavailable
  8 2026-09-01 12:05:08 ERROR HTTP 500 from /api/accounts/42
  9 2026-09-01 12:05:09 ERROR HTTP 404 from /api/accounts/42
```

### HTTP 500 from /api/accounts/42

Occurrences: 1

First occurrence: Line 8

Severity: ERROR

Context:

```text
  5 2026-09-01 12:05:05 ERROR request 9922 timed out after 5011ms
  6 2026-09-01 12:05:06 WARN slow query detected
  7 2026-09-01 12:05:07 CRITICAL database unavailable
> 8 2026-09-01 12:05:08 ERROR HTTP 500 from /api/accounts/42
  9 2026-09-01 12:05:09 ERROR HTTP 404 from /api/accounts/42
```

### HTTP 404 from /api/accounts/42

Occurrences: 1

First occurrence: Line 9

Severity: ERROR

Context:

```text
  6 2026-09-01 12:05:06 WARN slow query detected
  7 2026-09-01 12:05:07 CRITICAL database unavailable
  8 2026-09-01 12:05:08 ERROR HTTP 500 from /api/accounts/42
> 9 2026-09-01 12:05:09 ERROR HTTP 404 from /api/accounts/42
```

## First Critical Failure

Line 7: database unavailable

```text
  4 2026-09-01 12:05:04 INFO retrying request 9921
  5 2026-09-01 12:05:05 ERROR request 9922 timed out after 5011ms
  6 2026-09-01 12:05:06 WARN slow query detected
> 7 2026-09-01 12:05:07 CRITICAL database unavailable
  8 2026-09-01 12:05:08 ERROR HTTP 500 from /api/accounts/42
  9 2026-09-01 12:05:09 ERROR HTTP 404 from /api/accounts/42
```
