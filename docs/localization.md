# Localization

SOIPack provides localized error and warning messages in English and Turkish. The
localization system is shared across the CLI and the REST API to ensure that the
same codes return consistent messaging regardless of the surface.

## CLI usage

All CLI commands accept the global `--locale` option. The value can be either
`en` or `tr` (locale tags with regions such as `en-US` are normalized
automatically). The selected locale controls human readable error and warning
messages emitted by the logger.

```bash
# Show warnings and errors in English (default)
soipack --locale en run --config pipeline.yml

# Display the same messages in Turkish
soipack --locale tr run --config pipeline.yml
```
## REST API usage

The REST API inspects the standard `Accept-Language` request header and
localizes error responses accordingly. When a request fails, the response JSON
includes the localized message next to the stable error `code` value.

```http
GET /v1/jobs/not-a-valid-id HTTP/1.1
Authorization: Bearer <token>
Accept-Language: en-US,en;q=0.9
```

Example JSON response:

```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "The identifier value is not valid."
  }
}
```

Sending the same request with `Accept-Language: tr-TR` will return
`"message": "Kimlik değeri geçerli değil."`.

## Extending translations

Localization strings are defined in JSON catalogs under `packages/core/locales/`
with the translation keys referenced throughout the codebase. New message keys
should be added to both `en.json` and `tr.json`, and exercised through tests to
validate fallback behaviour for missing keys and locales.
