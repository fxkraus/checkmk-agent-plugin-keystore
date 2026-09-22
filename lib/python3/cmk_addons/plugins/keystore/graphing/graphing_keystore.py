"""Checkmk 2.4 graphing definitions for the Java Keystore certificate monitor."""

from cmk.graphing.v1 import Title
from cmk.graphing.v1.graphs import Graph, MinimalRange
from cmk.graphing.v1.metrics import Color, DecimalNotation, Metric, Unit

# ---------------------------------------------------------------------------
# Metric definitions
# ---------------------------------------------------------------------------

metric_days_remaining = Metric(
    name="days_remaining",
    title=Title("Nearest certificate expiry"),
    unit=Unit(DecimalNotation("d")),
    color=Color.YELLOW,
)

metric_cert_count = Metric(
    name="cert_count",
    title=Title("Monitored certificates"),
    unit=Unit(DecimalNotation("")),
    color=Color.BLUE,
)

# ---------------------------------------------------------------------------
# Graph definitions
# ---------------------------------------------------------------------------

graph_keystore_expiry = Graph(
    name="keystore_certificate_expiry",
    title=Title("Certificate expiry (nearest)"),
    simple_lines=["days_remaining"],
    minimal_range=MinimalRange(0, 90),
)
