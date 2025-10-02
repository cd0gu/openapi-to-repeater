# OpenAPI → Repeater (Burp Jython Extension)

Small Burp extension (Jython 2.7) that imports an OpenAPI (v3) spec and generates raw HTTP requests you can paste into Repeater — or send automatically to Repeater with UI-specified host, HTTPS toggle, bearer token and extra headers.

**Features**
- Parse OpenAPI (JSON or YAML converted) and synthesize example request bodies.
- UI fields for Target host, HTTPS toggle, Authorization (Bearer), and extra headers.
- Copy raw request to clipboard or send directly to Burp Repeater (best-effort across Burp versions).
- CRLF-normalized requests (ensures Repeater accepts the request).

## Repo layout
See the repository tree. Main extension source is `src/openapi_to_repeater.py`.

## Requirements
- Burp Suite (Professional or Community)
- Jython standalone jar (for Burp Extender Python support) — use Jython 2.7.x
- (Optional) Python 3 for converting YAML → JSON locally (PyYAML)

## Install
1. Download Jython standalone jar (2.7.x) and add it in Burp → Extender → Options → Python Environment.
2. In Burp → Extender → Extensions → Add:
   - Type: Python
   - Select `src/openapi_to_repeater.py`
3. Use the "Load OpenAPI JSON" button in the extension tab and follow instructions.

## Convert YAML to JSON (if needed)
If you have YAML spec: convert it:
```bash
pip install pyyaml
python -c "import yaml,json,sys; print(json.dumps(yaml.safe_load(open(sys.argv[1]))))" openapi.yaml > openapi_clean.json
