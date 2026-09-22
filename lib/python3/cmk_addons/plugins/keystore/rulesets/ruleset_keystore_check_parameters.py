"""Checkmk 2.4 ruleset for Java Keystore certificate check parameters."""

from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    Integer,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, HostAndItemCondition, Topic


def _parameter_form_keystore() -> Dictionary:
    return Dictionary(
        title=Title("Java Keystore Certificate Expiry"),
        help_text=Help("Configure warning and critical thresholds for certificate expiry in Java keystores (JKS and PKCS12)."),
        elements={
            "warn_days": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("Warning threshold"),
                    help_text=Help("Number of days before certificate expiry at which the check goes to WARNING state."),
                    unit_symbol="days",
                    prefill=DefaultValue(30),
                ),
            ),
            "crit_days": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("Critical threshold"),
                    help_text=Help("Number of days before certificate expiry at which the check goes to CRITICAL state."),
                    unit_symbol="days",
                    prefill=DefaultValue(14),
                ),
            ),
        },
    )


rule_spec_keystore = CheckParameters(
    name="keystore",
    title=Title("Java Keystore Certificate Expiry"),
    topic=Topic.APPLICATIONS,
    parameter_form=_parameter_form_keystore,
    condition=HostAndItemCondition(
        item_title=Title("Keystore path"),
    ),
)
