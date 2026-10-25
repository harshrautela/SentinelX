"""
OpenAPI Specification Parser
----------------------------
Parses OpenAPI 3.0.x and 3.1.x JSON/dict schemas.
Extracts normalized endpoint definitions, parameters, request schemas, and security requirements.
Resolves internal $ref references safely.
"""

from typing import Any, Dict, List, Optional
from app.discovery.endpoint_model import DiscoveredEndpointDTO, ParameterInfo
from app.core.logging import logger


class OpenAPIParser:
    """Parser for OpenAPI 3.x specifications."""

    def __init__(self, spec: Dict[str, Any]):
        self.spec = spec
        self.components = spec.get("components", {})
        self.schemas = self.components.get("schemas", {})
        self.security_schemes = self.components.get("securitySchemes", {})
        self.global_security = spec.get("security", [])

    def resolve_ref(self, ref: str, max_depth: int = 5) -> Dict[str, Any]:
        """
        Safely resolve internal $ref like '#/components/schemas/User'.
        Prevents circular reference loops with max_depth.
        """
        if max_depth <= 0 or not ref.startswith("#/"):
            return {}

        parts = ref.lstrip("#/").split("/")
        curr: Any = self.spec
        for part in parts:
            if isinstance(curr, dict) and part in curr:
                curr = curr[part]
            else:
                return {}

        if isinstance(curr, dict) and "$ref" in curr:
            return self.resolve_ref(curr["$ref"], max_depth=max_depth - 1)

        return curr if isinstance(curr, dict) else {}

    def extract_parameter(self, param_raw: Dict[str, Any]) -> ParameterInfo:
        """Parse an OpenAPI parameter object."""
        if "$ref" in param_raw:
            param_raw = self.resolve_ref(param_raw["$ref"])

        name = param_raw.get("name", "unknown")
        location = param_raw.get("in", "query")
        required = param_raw.get("required", location == "path")
        description = param_raw.get("description")
        
        schema = param_raw.get("schema", {})
        if "$ref" in schema:
            schema = self.resolve_ref(schema["$ref"])

        param_type = schema.get("type", "string")
        default_val = schema.get("default")
        example = param_raw.get("example") or schema.get("example")

        return ParameterInfo(
            name=name,
            location=location,
            required=required,
            param_type=param_type,
            description=description,
            default_value=default_val,
            example=example,
        )

    def extract_request_body_schema(self, request_body_raw: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Parse request body schema and resolve references."""
        if not request_body_raw:
            return None

        if "$ref" in request_body_raw:
            request_body_raw = self.resolve_ref(request_body_raw["$ref"])

        content = request_body_raw.get("content", {})
        json_content = content.get("application/json") or next(iter(content.values()), None)
        if not json_content:
            return None

        schema = json_content.get("schema", {})
        if "$ref" in schema:
            schema = self.resolve_ref(schema["$ref"])

        return schema

    def extract_endpoints(self) -> List[DiscoveredEndpointDTO]:
        """
        Parse all paths and operations into normalized DiscoveredEndpointDTO objects.
        """
        endpoints: List[DiscoveredEndpointDTO] = []
        paths: Dict[str, Any] = self.spec.get("paths", {})

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            # Shared path-level parameters
            path_level_params: List[ParameterInfo] = []
            if "parameters" in path_item and isinstance(path_item["parameters"], list):
                for p in path_item["parameters"]:
                    path_level_params.append(self.extract_parameter(p))

            # HTTP Methods
            for method in ["get", "post", "put", "delete", "patch", "options", "head"]:
                if method not in path_item:
                    continue

                operation = path_item[method]
                if not isinstance(operation, dict):
                    continue

                # Combine parameters (operation level overrides path level by name+location)
                operation_params: List[ParameterInfo] = list(path_level_params)
                if "parameters" in operation and isinstance(operation["parameters"], list):
                    for p in operation["parameters"]:
                        parsed_p = self.extract_parameter(p)
                        # Replace if already exists with same name & location
                        existing_idx = next(
                            (i for i, ep in enumerate(operation_params) if ep.name == parsed_p.name and ep.location == parsed_p.location),
                            None
                        )
                        if existing_idx is not None:
                            operation_params[existing_idx] = parsed_p
                        else:
                            operation_params.append(parsed_p)

                # Request body schema
                request_body_schema = self.extract_request_body_schema(operation.get("requestBody"))

                # Security / Authentication determination
                # If operation specifies `security`, use that; otherwise fall back to global `security`
                op_security = operation.get("security", self.global_security)
                auth_required = False
                auth_schemes: List[str] = []

                if op_security:
                    # An empty dict `{}` inside security array indicates optional authentication
                    for sec_req in op_security:
                        if sec_req and isinstance(sec_req, dict):
                            for scheme_name in sec_req.keys():
                                auth_schemes.append(scheme_name)
                                auth_required = True

                endpoints.append(
                    DiscoveredEndpointDTO(
                        method=method.upper(),
                        path=path,
                        summary=operation.get("summary"),
                        description=operation.get("description"),
                        parameters=operation_params,
                        request_body_schema=request_body_schema,
                        response_schema=operation.get("responses"),
                        auth_required=auth_required,
                        auth_schemes=list(set(auth_schemes)),
                        tags=operation.get("tags", []),
                    )
                )

        logger.info(f"OpenAPIParser successfully parsed {len(endpoints)} endpoints from specification.")
        return endpoints
