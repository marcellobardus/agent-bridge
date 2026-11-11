"""Agent Bridge client (stdlib only). See clients/python/README.md."""
from .client import (MESSAGE_TYPES, STATES, AuthError, BridgeClient, BridgeError, ConfigError, TransientError,
                     action_sha256, canonical_json, event_key, redact)
from .guard import GuardConfig, Verdict, as_prompt_block, classify, quarantine_summary, unwrap, wrap
from .poller import default_quarantine_path, default_state_path, load_state, poll_once, read_quarantine, save_state

__version__ = "1.0.0"
__all__ = ["BridgeClient", "BridgeError", "TransientError", "AuthError", "ConfigError", "action_sha256",
           "canonical_json", "event_key", "redact", "poll_once", "load_state", "save_state", "default_state_path",
           "MESSAGE_TYPES", "STATES", "classify", "wrap", "as_prompt_block", "quarantine_summary", "unwrap", "Verdict", "GuardConfig",
           "read_quarantine", "default_quarantine_path"]
