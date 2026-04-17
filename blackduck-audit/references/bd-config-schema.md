# bd-config.json Schema

## Required Fields

| Field | Type | Description |
|---|---|---|
| `baseUrl` | string | BlackDuck server base URL, e.g. `"https://blackduck.example.com"` |
| `accessToken` | string | Personal access token from BlackDuck UI |
| `projectName` | string | Exact project name as shown in BlackDuck |
| `versionName` | string | Exact version name to audit |
| `filters` | object | Optional BOM filter params (see below) |

## Supported Filter Keys

| Key | Example values |
|---|---|
| `reviewStatus` | `"NOT_REVIEWED"`, `"REVIEWED"` |
| `policyStatus` | `"IN_VIOLATION"`, `"NOT_IN_VIOLATION"` |
| `approvalStatus` | `"APPROVED"`, `"REJECTED"` |

## Example bd-config.json

```json
{
  "baseUrl": "https://blackduck.example.com",
  "accessToken": "your-token-here",
  "projectName": "my-android-project",
  "versionName": "1.0.0",
  "filters": {
    "reviewStatus": "NOT_REVIEWED"
  }
}
```

## Notes

- The `filters` object is optional; omit or set to `{}` to fetch all BOM components.
- `accessToken` is a BlackDuck personal access token (not username/password). Generate
  it from: BlackDuck UI → user icon → My Access Tokens.
- `projectName` and `versionName` must match exactly (case-sensitive).
