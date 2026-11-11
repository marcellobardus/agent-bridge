"""Export the agent API OpenAPI schema to docs/openapi.json (no DB or credentials needed)."""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from bridge.api.app import create_app  # noqa: E402
from bridge.config import Settings  # noqa: E402

out = pathlib.Path(__file__).resolve().parents[1] / "docs" / "openapi.json"
schema = create_app(Settings(db_path="/nonexistent/bridge.db")).openapi()
out.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n")
print(f"wrote {out} ({len(schema['paths'])} paths)")
