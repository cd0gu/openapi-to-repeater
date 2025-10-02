# OpenAPI → Repeater (Burp Extension)

A simple Burp Suite extension (Jython 2.7) that imports an OpenAPI spec and generates HTTP requests you can send directly to Repeater.

## Features
- Parse OpenAPI (JSON converted) and generate requests
- UI inputs for:
  - Target host
  - HTTPS toggle
  - Authorization (Bearer token)
  - Extra headers
- Copy raw request to clipboard or send to Repeater

## Install
1. In Burp → Extender → Options → Python Environment: add Jython standalone 2.7 jar.
2. In Burp → Extender → Extensions → Add:
   - Type: Python
   - Select `src/openapi_to_repeater.py`
3. In the new tab, click **Load OpenAPI JSON**.

## Example
See [`examples/openapi.json`](examples/openapi.json).

## License
MIT
