import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    logger.info("FULL EVENT: %s", json.dumps(event, default=str))

    detail = event.get("detail", {}) if isinstance(event, dict) else {}
    findings = detail.get("findings", []) or []

    logger.info(
        "summary: source=%s detail-type=%s region=%s findings=%d",
        event.get("source"),
        event.get("detail-type"),
        event.get("region"),
        len(findings),
    )

    for f in findings:
        compliance = f.get("Compliance", {}) or {}
        workflow = f.get("Workflow", {}) or {}
        resources = f.get("Resources", []) or []
        resource_ids = [r.get("Id") for r in resources]
        logger.info(
            "finding: control=%s compliance=%s workflow=%s updated=%s region=%s resources=%s id=%s",
            compliance.get("SecurityControlId"),
            compliance.get("Status"),
            workflow.get("Status"),
            f.get("UpdatedAt"),
            f.get("Region"),
            resource_ids,
            f.get("Id"),
        )

    return {"ok": True, "findings_logged": len(findings)}
