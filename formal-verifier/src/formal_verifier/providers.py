from typing import Any


def verify_with_z3(policy: dict[str, Any]) -> dict[str, Any]:
    # TODO: 对接 z3-solver
    return {"engine": "z3", "result": "SKIPPED", "reason": "not_implemented"}


def verify_with_opa(policy: dict[str, Any]) -> dict[str, Any]:
    # TODO: 对接 OPA / Rego
    return {"engine": "opa", "result": "SKIPPED", "reason": "not_implemented"}

