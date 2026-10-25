"""
Unit tests for OpenAPI Parser
"""

from app.discovery.openapi_parser import OpenAPIParser


def test_openapi_parser_extracts_endpoints(sample_openapi_spec):
    """Verify that parser extracts all paths, methods, parameters, and auth requirements."""
    parser = OpenAPIParser(sample_openapi_spec)
    endpoints = parser.extract_endpoints()

    assert len(endpoints) == 4
    paths = {ep.path for ep in endpoints}
    assert "/api/v1/users/{id}" in paths
    assert "/api/v1/accounts/{account_id}" in paths
    assert "/api/v1/search" in paths
    assert "/api/v1/admin/users" in paths

    # Check user endpoint parameters and auth
    user_ep = next(ep for ep in endpoints if ep.path == "/api/v1/users/{id}")
    assert user_ep.method == "GET"
    assert user_ep.auth_required is True
    assert "bearerAuth" in user_ep.auth_schemes
    assert len(user_ep.parameters) == 1
    assert user_ep.parameters[0].name == "id"
    assert user_ep.parameters[0].location == "path"
    assert user_ep.parameters[0].param_type == "integer"

    # Check search endpoint query parameter
    search_ep = next(ep for ep in endpoints if ep.path == "/api/v1/search")
    assert len(search_ep.parameters) == 1
    assert search_ep.parameters[0].name == "q"
    assert search_ep.parameters[0].location == "query"


def test_openapi_parser_resolves_refs():
    """Verify that $ref references are safely resolved."""
    spec_with_ref = {
        "openapi": "3.0.0",
        "paths": {
            "/api/v1/profile": {
                "post": {
                    "requestBody": {
                        "$ref": "#/components/requestBodies/UserBody"
                    },
                    "responses": {"200": {"description": "OK"}}
                }
            }
        },
        "components": {
            "requestBodies": {
                "UserBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {"name": {"type": "string"}}
                            }
                        }
                    }
                }
            }
        }
    }

    parser = OpenAPIParser(spec_with_ref)
    endpoints = parser.extract_endpoints()
    assert len(endpoints) == 1
    ep = endpoints[0]
    assert ep.request_body_schema is not None
    assert ep.request_body_schema.get("type") == "object"
    assert "name" in ep.request_body_schema.get("properties", {})
