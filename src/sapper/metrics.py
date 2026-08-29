"""The PROVENANCE metric (PLAN.md §3) without cloudwatch:PutMetricData: CloudWatch
Logs extracts metrics from a log line written in embedded metric format
(vendor spec, CloudWatch_Embedded_Metric_Format_Specification). One document
per finding carries ProvenanceDrop 1 or 0, so the metric's average over a
period is the drop rate P3's sustained-100% alarm watches.
"""

from datetime import datetime
from typing import Any

METRIC_NAMESPACE = "sapper"
PROVENANCE_DROP_METRIC = "ProvenanceDrop"
MILLISECONDS_PER_SECOND = 1000


def with_provenance_metric(
    fields: dict[str, Any], dropped: bool, now: datetime
) -> dict[str, Any]:
    return {
        **fields,
        PROVENANCE_DROP_METRIC: int(dropped),
        "_aws": {
            "Timestamp": int(now.timestamp() * MILLISECONDS_PER_SECOND),
            "CloudWatchMetrics": [
                {
                    "Namespace": METRIC_NAMESPACE,
                    "Dimensions": [[]],
                    "Metrics": [{"Name": PROVENANCE_DROP_METRIC, "Unit": "Count"}],
                }
            ],
        },
    }
