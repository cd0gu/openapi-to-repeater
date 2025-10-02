# -*- coding: utf-8 -*-
"""
OpenAPI -> Repeater Burp extension (Jython)
- UI inputs for Target host, HTTPS toggle, Bearer token, Extra headers
- Sends selected request directly to Repeater with injected headers
- Ensures final CRLF so raw HTTP is valid

Jython 2.7 compatible.
"""

from __future__ import print_function
import json
import threading
import traceback

# Java imports
from java.awt import BorderLayout, Dimension, Toolkit
from java.awt.datatransfer import StringSelection
from javax.swing import (
    JPanel, JButton, JScrollPane, JTextArea, JFileChooser, JOptionPane,
    DefaultListModel, JList, BoxLayout, JLabel, JTextField, JCheckBox
)

# Burp API
from burp import IBurpExtender, ITab


# -------------------- Helpers --------------------

def copy_to_clipboard(text):
    try:
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(text), None)
        return True
    except Exception as e:
        try:
            print("Clipboard copy failed:", e)
        except:
            pass
        return False


def simple_sample_from_schema(schema, spec):
    if not schema:
        return None
    if "$ref" in schema:
        ref = schema["$ref"]
        if ref.startswith("#/"):
            parts = ref.lstrip("#/").split("/")
            node = spec
            for p in parts:
                if isinstance(node, dict) and p in node:
                    node = node[p]
                else:
                    node = {}
                    break
            return simple_sample_from_schema(node, spec)
        return "example"
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]

    t = schema.get("type")
    if not t:
        if "properties" in schema:
            t = "object"
        elif "enum" in schema:
            enums = schema.get("enum")
            if isinstance(enums, (list, tuple)) and enums:
                return enums[0]
            return "example"
        else:
            t = "string"

    if t == "string":
        fmt = schema.get("format", "")
        if fmt == "date-time":
            return "2025-10-02T12:00:00Z"
        if fmt == "date":
            return "2025-10-02"
        if fmt == "email":
            return "user@example.com"
        if fmt == "uuid":
            return "00000000-0000-0000-0000-000000000000"
        return schema.get("title") or schema.get("name") or "example"

    if t in ("integer", "number"):
        if "minimum" in schema:
            try:
                return int(schema.get("minimum"))
            except:
                return 1
        if "maximum" in schema:
            try:
                return int(schema.get("maximum"))
            except:
                return 1
        return 1

    if t == "boolean":
        return False

    if t == "array":
        items = schema.get("items", {"type": "string"})
        return [simple_sample_from_schema(items, spec)]

    if t == "object":
        props = schema.get("properties", {})
        obj = {}
        for k, subschema in props.items():
            obj[k] = simple_sample_from_schema(subschema, spec)
        return obj

    return "example"


def parse_extra_headers(textarea_value):
    headers = {}
    if not textarea_value:
        return headers
    for raw in textarea_value.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":", 1)
        if len(parts) != 2:
            continue
        name = parts[0].strip()
        value = parts[1].strip()
        if name:
            headers[name] = value
    return headers


def normalize_crlf(s):
    """
    Convert LF to CRLF, and ensure the request ends with an extra CRLF.
    """
    # First normalize all line breaks to LF to avoid mixing
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    # Then convert to CRLF
    s = s.replace("\n", "\r\n")
    # Ensure final CRLF (one extra line) so Repeater sees a complete request
    if not s.endswith("\r\n"):
        s += "\r\n"
    return s


def parse_host_and_port(host_field, use_https):
    """
    host_field may be:
      - "example.com"
      - "example.com:8443"
      - "http://example.com" (we strip scheme)
      - "https://example.com:444"
    Returns (host, port) where port is derived from use_https if not provided.
    """
    host_field = host_field.strip()
    if host_field.startswith("http://"):
        host_field = host_field[len("http://"):]
        # If user ticked HTTPS, honor the checkbox, not the stripped scheme.
    elif host_field.startswith("https://"):
        host_field = host_field[len("https://"):]
    # Remove any trailing path after slash
    if "/" in host_field:
        host_field = host_field.split("/")[0]

    host = host_field
    port = None
    if ":" in host_field:
        parts = host_field.split(":", 1)
        host = parts[0]
        try:
            port = int(parts[1])
        except:
            port = None

    if port is None:
        port = 443 if use_https else 80
    return host, port


# -------------------- Burp extension class --------------------

class BurpExtender(IBurpExtender, ITab):
    """
    Burp entry point.
    """

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = callbacks.getStdout()
        self._stderr = callbacks.getStderr()
        callbacks.setExtensionName("OpenAPI -> Repeater")

        # UI
        self._panel = JPanel(BorderLayout())

        # Top: Load + inputs
        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.X_AXIS))

        btn_load = JButton("Load OpenAPI JSON", actionPerformed=self.load_openapi)
        top.add(btn_load)

        top.add(JLabel(" Target host: "))
        self.txt_host = JTextField(24)
        self.txt_host.setText("")  # user provides

        top.add(self.txt_host)

        self.chk_https = JCheckBox("HTTPS", True)
        top.add(self.chk_https)

        top.add(JLabel(" Authorization (Bearer token): "))
        self.txt_bearer = JTextField(30)
        self.txt_bearer.setText("")
        top.add(self.txt_bearer)

        self._panel.add(top, BorderLayout.NORTH)

        # Center: list + extra headers + buttons
        center = JPanel()
        center.setLayout(BoxLayout(center, BoxLayout.Y_AXIS))

        self._list_model = DefaultListModel()
        self._req_list = JList(self._list_model)
        self._req_list.setVisibleRowCount(14)
        center.add(JScrollPane(self._req_list))

        extra_panel = JPanel()
        extra_panel.setLayout(BoxLayout(extra_panel, BoxLayout.Y_AXIS))
        extra_panel.add(JLabel(" Extra headers (one per line, e.g., 'X-Debug: 1')"))
        self.ta_extra_headers = JTextArea(4, 60)
        center.add(extra_panel)
        center.add(JScrollPane(self.ta_extra_headers))

        btn_panel = JPanel()
        btn_send = JButton("Send to Repeater", actionPerformed=self.send_selected_to_repeater)
        btn_copy = JButton("Copy Raw", actionPerformed=self.copy_selected_to_clipboard)
        btn_view = JButton("View Raw", actionPerformed=self.view_selected_raw)
        btn_panel.add(btn_send)
        btn_panel.add(btn_copy)
        btn_panel.add(btn_view)
        center.add(btn_panel)

        self._panel.add(center, BorderLayout.CENTER)

        callbacks.addSuiteTab(self)

        # storage
        self._generated = []  # entries: {label, raw_base, headers_base}
        self._spec = None

    # ITab
    def getTabCaption(self):
        return "OpenAPI->Repeater"

    def getUiComponent(self):
        return self._panel

    # Load action
    def load_openapi(self, evt):
        try:
            fc = JFileChooser()
            res = fc.showOpenDialog(self._panel)
            if res == JFileChooser.APPROVE_OPTION:
                f = fc.getSelectedFile()
                path = f.getAbsolutePath()
                fh = open(path, "r")
                try:
                    spec = json.load(fh)
                finally:
                    fh.close()
                self._spec = spec
                t = threading.Thread(target=self.parse_and_generate, args=(spec,))
                t.start()
        except Exception as e:
            traceback.print_exc()
            JOptionPane.showMessageDialog(self._panel, "Failed to load JSON: %s" % str(e))

    # Parse and generate (no static host defaults)
    def parse_and_generate(self, spec):
        try:
            generated = []
            paths = spec.get("paths", {})
            for path_template, path_item in paths.items():
                path_params_global = path_item.get("parameters", []) or []
                for method in ("get", "post", "put", "patch", "delete", "head", "options"):
                    if method not in path_item:
                        continue
                    op = path_item[method]
                    params = []
                    params.extend(path_params_global)
                    params.extend(op.get("parameters", []) or [])

                    path_params = {}
                    query_params = {}
                    header_params = {}

                    for p in params:
                        if isinstance(p, dict) and "$ref" in p:
                            ref = p["$ref"]
                            if ref.startswith("#/"):
                                parts = ref.lstrip("#/").split("/")
                                node = spec
                                for part in parts:
                                    node = node.get(part, {})
                                p = node
                            else:
                                p = {}
                        name = p.get("name")
                        location = p.get("in")
                        schema = p.get("schema") or {}
                        example = p.get("example")
                        if example is None:
                            val = simple_sample_from_schema(schema, spec)
                        else:
                            val = example
                        if location == "path":
                            path_params[name] = val
                        elif location == "query":
                            query_params[name] = val
                        elif location == "header":
                            header_params[name] = val

                    headers_base = {"User-Agent": "OpenAPI-to-Repeater/1.0", "Accept": "application/json"}
                    for hk, hv in header_params.items():
                        headers_base[str(hk)] = str(hv)

                    body_obj = None
                    if "requestBody" in op:
                        rb = op["requestBody"]
                        if isinstance(rb, dict) and "$ref" in rb:
                            ref = rb["$ref"]
                            if ref.startswith("#/"):
                                parts = ref.lstrip("#/").split("/")
                                node = spec
                                for part in parts:
                                    node = node.get(part, {})
                                rb = node
                            else:
                                rb = {}
                        if isinstance(rb, dict):
                            content = rb.get("content", {})
                            if "application/json" in content:
                                media = content["application/json"]
                                schema = media.get("schema", {})
                                body_obj = simple_sample_from_schema(schema, spec)
                                headers_base["Content-Type"] = "application/json"
                            else:
                                for ct, media in content.items():
                                    schema = media.get("schema", {})
                                    body_obj = simple_sample_from_schema(schema, spec)
                                    headers_base["Content-Type"] = ct
                                    break

                    final_path = path_template
                    for k, v in path_params.items():
                        final_path = final_path.replace("{" + k + "}", str(v))

                    qs = ""
                    if query_params:
                        pairs = []
                        for k, v in query_params.items():
                            pairs.append("%s=%s" % (self._url_encode(str(k)), self._url_encode(str(v))))
                        qs = "?" + "&".join(pairs)

                    request_line = "%s %s%s HTTP/1.1" % (method.upper(), final_path, qs)

                    lines = [request_line]
                    # Host will be added at send time
                    for hk, hv in headers_base.items():
                        lines.append("%s: %s" % (hk, hv))
                    lines.append("")
                    if body_obj is not None:
                        try:
                            lines.append(json.dumps(body_obj, indent=2, ensure_ascii=False))
                        except:
                            lines.append(str(body_obj))

                    raw_base = "\n".join(lines)
                    label = "%s %s" % (method.upper(), path_template)
                    generated.append({
                        "label": label,
                        "raw_base": raw_base,
                        "headers_base": headers_base
                    })

            self._callbacks.printOutput("Generated %d requests" % len(generated))
            self._generated = generated
            self._list_model.clear()
            for it in generated:
                self._list_model.addElement(it["label"])
        except Exception as e:
            traceback.print_exc()
            JOptionPane.showMessageDialog(self._panel, "Parsing failed: %s" % str(e))

    def _url_encode(self, s):
        try:
            from java.net import URLEncoder
            return URLEncoder.encode(s, "UTF-8")
        except:
            return s.replace(" ", "%20")

    def get_selected_index(self):
        return self._req_list.getSelectedIndex()

    def get_selected_item(self):
        idx = self.get_selected_index()
        if idx < 0 or idx >= len(self._generated):
            return None
        return self._generated[idx]

    # Build final raw with Host + headers + token, CRLF normalized
    def _build_final_raw(self, base, host, bearer_token, extra_headers_dict):
        lines = base.split("\n")
        request_line = lines[0] if lines else ""
        rest = lines[1:] if len(lines) > 1 else []

        # Insert Host first
        new_lines = [request_line, "Host: %s" % host]

        # Split existing headers/body
        body_index = None
        for i, l in enumerate(rest):
            if l.strip() == "":
                body_index = i
                break
        headers_part = rest if body_index is None else rest[:body_index]
        body_part = [] if body_index is None else rest[body_index+1:]

        # Build a map of existing headers
        existing = {}
        for h in headers_part:
            if ":" in h:
                k, v = h.split(":", 1)
                existing[k.strip()] = v.strip()

        # Inject/override Authorization if a token is provided
        if bearer_token:
            existing["Authorization"] = "Bearer %s" % bearer_token

        # Merge extra headers (override existing)
        for k, v in (extra_headers_dict or {}).items():
            if k.lower() == "host":
                # Host is already injected; ignore any "Host:" from extra headers
                continue
            existing[k] = v

        # Emit headers
        for k, v in existing.items():
            if k.lower() == "host":
                continue
            new_lines.append("%s: %s" % (k, v))

        # Header/body separator
        new_lines.append("")
        # Body (if any)
        new_lines.extend(body_part)

        final_raw = "\n".join(new_lines)
        # Normalize line breaks to CRLF and ensure trailing CRLF
        final_raw = normalize_crlf(final_raw)
        return final_raw

    def copy_selected_to_clipboard(self, evt):
        it = self.get_selected_item()
        if not it:
            JOptionPane.showMessageDialog(self._panel, "Select a request first")
            return

        host_field = self.txt_host.getText().strip()
        if not host_field:
            JOptionPane.showMessageDialog(self._panel, "Target host is empty.")
            return

        use_https = bool(self.chk_https.isSelected())
        host, port = parse_host_and_port(host_field, use_https)

        extras = parse_extra_headers(self.ta_extra_headers.getText())
        bearer = self.txt_bearer.getText().strip()

        final_raw = self._build_final_raw(it["raw_base"], host_field, bearer, extras)
        ok = copy_to_clipboard(final_raw)
        if ok:
            JOptionPane.showMessageDialog(self._panel, "Raw request copied to clipboard.")
        else:
            ta = JTextArea(final_raw)
            ta.setLineWrap(True)
            ta.setWrapStyleWord(True)
            sp = JScrollPane(ta)
            sp.setPreferredSize(Dimension(900, 480))
            JOptionPane.showMessageDialog(self._panel, sp, "Raw Request (copy manually)", JOptionPane.PLAIN_MESSAGE)

    def view_selected_raw(self, evt):
        it = self.get_selected_item()
        if not it:
            JOptionPane.showMessageDialog(self._panel, "Select a request first")
            return

        host_field = self.txt_host.getText().strip()
        if not host_field:
            JOptionPane.showMessageDialog(self._panel, "Target host is empty.")
            return

        extras = parse_extra_headers(self.ta_extra_headers.getText())
        bearer = self.txt_bearer.getText().strip()
        final_raw = self._build_final_raw(it["raw_base"], host_field, bearer, extras)

        ta = JTextArea(final_raw)
        ta.setLineWrap(True)
        ta.setWrapStyleWord(True)
        sp = JScrollPane(ta)
        sp.setPreferredSize(Dimension(900, 480))
        JOptionPane.showMessageDialog(self._panel, sp, "Raw Request (preview)", JOptionPane.PLAIN_MESSAGE)

    def send_selected_to_repeater(self, evt):
        it = self.get_selected_item()
        if not it:
            JOptionPane.showMessageDialog(self._panel, "Select a request first")
            return
        try:
            host_field = self.txt_host.getText().strip()
            if not host_field:
                JOptionPane.showMessageDialog(self._panel, "Target host is empty.")
                return

            use_https = bool(self.chk_https.isSelected())
            host, port = parse_host_and_port(host_field, use_https)

            extras = parse_extra_headers(self.ta_extra_headers.getText())
            bearer = self.txt_bearer.getText().strip()

            final_raw = self._build_final_raw(it["raw_base"], host_field, bearer, extras)

            try:
                req_bytes = final_raw.encode("utf-8")
            except Exception:
                req_bytes = final_raw

            sent = False
            cb = self._callbacks
            if hasattr(cb, "sendToRepeater"):
                try:
                    # Correct signature (with tab caption):
                    # sendToRepeater(String host, int port, boolean useHttps, byte[] request, String tabCaption)
                    cb.sendToRepeater(host, int(port), bool(use_https), req_bytes, "OpenAPI")
                    JOptionPane.showMessageDialog(self._panel, "Sent to Repeater.")
                    sent = True
                except Exception as e:
                    try:
                        # Fallback variant without caption (older Burp):
                        cb.sendToRepeater(host, int(port), bool(use_https), req_bytes)
                        JOptionPane.showMessageDialog(self._panel, "Sent to Repeater (fallback).")
                        sent = True
                    except Exception as e2:
                        sent = False

            if not sent:
                ok = copy_to_clipboard(final_raw)
                if ok:
                    JOptionPane.showMessageDialog(self._panel, "Could not auto-send. Request copied to clipboard.")
                else:
                    ta = JTextArea(final_raw)
                    ta.setLineWrap(True)
                    ta.setWrapStyleWord(True)
                    sp = JScrollPane(ta)
                    sp.setPreferredSize(Dimension(900, 480))
                    JOptionPane.showMessageDialog(self._panel, sp, "Could not auto-send. Copy manually.", JOptionPane.PLAIN_MESSAGE)
        except Exception as e:
            traceback.print_exc()
            JOptionPane.showMessageDialog(self._panel, "Failed to send: %s" % str(e))
