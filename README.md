# OpenAPI → Repeater (Burp Extension)

A simple Burp Suite extension (Jython 2.7) that imports an OpenAPI specification and generates HTTP requests you can copy to clipboard or send directly to Repeater.  

## Features
- Import OpenAPI v3 (JSON format) and generate example requests  
- UI fields for:
  - Target host (with optional `:port`)
  - HTTPS toggle
  - Authorization (Bearer token)
  - Extra headers  
- Normalize CRLF line endings to ensure valid raw HTTP  
- Copy raw requests to clipboard or send directly to Repeater  

## Installation
1. Download **Jython standalone 2.7.x** and add it in Burp → Extender → Options → Python Environment.  
2. In Burp → Extender → Extensions → Add:  
   - Type: Python  
   - Select `src/openapi_to_repeater.py`  
3. A new **OpenAPI→Repeater** tab will appear in Burp.  

## Usage
1. Click **Load OpenAPI JSON** and select your spec file.  
2. Enter target host (with optional port) and adjust HTTPS checkbox.  
3. (Optional) Add a Bearer token and any extra headers.  
4. Select a request from the list.  
   - **Send to Repeater** → pushes request directly into Repeater  
   - **Copy Raw** → copies the raw HTTP request to clipboard  
   - **View Raw** → preview the generated request  

## Converting YAML to JSON
If your OpenAPI specification is in **YAML**, convert it to **JSON** before loading:  

```bash
pip install pyyaml
python -c "import yaml,json,sys; print(json.dumps(yaml.safe_load(open(sys.argv[1]))))" openapi.yaml > openapi.json
