from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from .errors import EngineError


class _SchemaValidator:
    def __init__(self, root_schema: dict[str, Any]) -> None:
        self.root_schema = root_schema
        self.errors: list[str] = []

    def validate(self, instance: Any) -> list[str]:
        self.errors = []
        self._validate(instance, self.root_schema, "$", self.root_schema)
        return self.errors

    def _error(self, path: str, message: str) -> None:
        if len(self.errors) < 50:
            self.errors.append(f"{path}: {message}")

    def _resolve_ref(self, reference: str) -> dict[str, Any]:
        if not reference.startswith("#/"):
            raise EngineError("unsupported_schema_reference", f"Only local JSON Schema references are supported: {reference}")
        current: Any = self.root_schema
        for raw in reference[2:].split("/"):
            token = raw.replace("~1", "/").replace("~0", "~")
            if not isinstance(current, dict) or token not in current:
                raise EngineError("invalid_schema_reference", f"Unable to resolve JSON Schema reference: {reference}")
            current = current[token]
        if not isinstance(current, dict):
            raise EngineError("invalid_schema_reference", f"JSON Schema reference does not resolve to an object: {reference}")
        return current

    @staticmethod
    def _type_matches(instance: Any, expected: str) -> bool:
        if expected == "null":
            return instance is None
        if expected == "object":
            return isinstance(instance, dict)
        if expected == "array":
            return isinstance(instance, list)
        if expected == "string":
            return isinstance(instance, str)
        if expected == "boolean":
            return isinstance(instance, bool)
        if expected == "integer":
            return isinstance(instance, int) and not isinstance(instance, bool)
        if expected == "number":
            return isinstance(instance, (int, float)) and not isinstance(instance, bool)
        return True

    def _matches(self, instance: Any, schema: dict[str, Any]) -> bool:
        nested = _SchemaValidator(self.root_schema)
        nested._validate(instance, schema, "$", self.root_schema)
        return not nested.errors

    def _validate(self, instance: Any, schema: Any, path: str, root_schema: dict[str, Any]) -> None:
        if schema is True:
            return
        if schema is False:
            self._error(path, "value is forbidden by schema")
            return
        if not isinstance(schema, dict):
            self._error(path, "schema node is not an object")
            return
        if "$ref" in schema:
            self._validate(instance, self._resolve_ref(str(schema["$ref"])), path, root_schema)
            return

        for subschema in schema.get("allOf", []):
            self._validate(instance, subschema, path, root_schema)
        if "anyOf" in schema and not any(self._matches(instance, subschema) for subschema in schema["anyOf"]):
            self._error(path, "does not satisfy any allowed schema")
        if "oneOf" in schema:
            matched = sum(1 for subschema in schema["oneOf"] if self._matches(instance, subschema))
            if matched != 1:
                self._error(path, f"must satisfy exactly one schema (matched {matched})")
        if "not" in schema and self._matches(instance, schema["not"]):
            self._error(path, "matches a forbidden schema")
        if "if" in schema:
            branch = schema.get("then") if self._matches(instance, schema["if"]) else schema.get("else")
            if branch is not None:
                self._validate(instance, branch, path, root_schema)

        if "const" in schema and instance != schema["const"]:
            self._error(path, f"must equal {schema['const']!r}")
        if "enum" in schema and instance not in schema["enum"]:
            self._error(path, f"must be one of {schema['enum']!r}")

        expected_type = schema.get("type")
        if expected_type is not None:
            allowed = expected_type if isinstance(expected_type, list) else [expected_type]
            if not any(self._type_matches(instance, str(item)) for item in allowed):
                self._error(path, f"must have type {allowed!r}")
                return

        if isinstance(instance, dict):
            required = schema.get("required", [])
            for name in required:
                if name not in instance:
                    self._error(path, f"missing required property {name!r}")
            properties = schema.get("properties", {})
            if isinstance(properties, dict):
                for name, subschema in properties.items():
                    if name in instance:
                        self._validate(instance[name], subschema, f"{path}.{name}", root_schema)
            additional = schema.get("additionalProperties", True)
            known = set(properties) if isinstance(properties, dict) else set()
            for name, value in instance.items():
                if name in known:
                    continue
                if additional is False:
                    self._error(path, f"unexpected property {name!r}")
                elif isinstance(additional, dict):
                    self._validate(value, additional, f"{path}.{name}", root_schema)
            minimum = schema.get("minProperties")
            maximum = schema.get("maxProperties")
            if minimum is not None and len(instance) < int(minimum):
                self._error(path, f"must contain at least {minimum} properties")
            if maximum is not None and len(instance) > int(maximum):
                self._error(path, f"must contain at most {maximum} properties")

        if isinstance(instance, list):
            if "minItems" in schema and len(instance) < int(schema["minItems"]):
                self._error(path, f"must contain at least {schema['minItems']} items")
            if "maxItems" in schema and len(instance) > int(schema["maxItems"]):
                self._error(path, f"must contain at most {schema['maxItems']} items")
            if schema.get("uniqueItems"):
                encoded = [json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False) for item in instance]
                if len(encoded) != len(set(encoded)):
                    self._error(path, "must contain unique items")
            item_schema = schema.get("items")
            if item_schema is not None:
                for index, value in enumerate(instance):
                    self._validate(value, item_schema, f"{path}[{index}]", root_schema)
            if "contains" in schema:
                matched = sum(1 for value in instance if self._matches(value, schema["contains"]))
                minimum = int(schema.get("minContains", 1))
                maximum = schema.get("maxContains")
                if matched < minimum:
                    self._error(path, f"must contain at least {minimum} matching item(s)")
                if maximum is not None and matched > int(maximum):
                    self._error(path, f"must contain at most {maximum} matching item(s)")

        if isinstance(instance, str):
            if "minLength" in schema and len(instance) < int(schema["minLength"]):
                self._error(path, f"must contain at least {schema['minLength']} characters")
            if "maxLength" in schema and len(instance) > int(schema["maxLength"]):
                self._error(path, f"must contain at most {schema['maxLength']} characters")
            if "pattern" in schema and re.search(str(schema["pattern"]), instance) is None:
                self._error(path, f"must match pattern {schema['pattern']!r}")
            if schema.get("format") == "date-time":
                try:
                    parsed = datetime.fromisoformat(instance.replace("Z", "+00:00"))
                    if parsed.tzinfo is None:
                        raise ValueError("timezone missing")
                except ValueError:
                    self._error(path, "must be an RFC 3339 date-time with timezone")

        if isinstance(instance, (int, float)) and not isinstance(instance, bool):
            if "minimum" in schema and instance < schema["minimum"]:
                self._error(path, f"must be >= {schema['minimum']}")
            if "maximum" in schema and instance > schema["maximum"]:
                self._error(path, f"must be <= {schema['maximum']}")


def load_schema(schema_path: Path) -> dict[str, Any]:
    try:
        value = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EngineError("schema_load_failed", f"Unable to load schema {schema_path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise EngineError("schema_load_failed", f"Schema {schema_path.name} must be an object.")
    return value


def validate_against_schema(document: Any, schema_path: Path, document_name: str) -> None:
    schema = load_schema(schema_path)
    errors = _SchemaValidator(schema).validate(document)
    if errors:
        raise EngineError(
            "schema_validation_failed",
            f"{document_name} failed strict schema validation: {errors[0]}",
            {"document": document_name, "errors": errors},
        )
