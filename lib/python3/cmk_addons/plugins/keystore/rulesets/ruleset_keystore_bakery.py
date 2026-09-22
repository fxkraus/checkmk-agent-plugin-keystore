"""Checkmk 2.4 ruleset for deploying the Java Keystore agent plugin via the Agent Bakery."""

from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    CascadingSingleChoice,
    CascadingSingleChoiceElement,
    DefaultValue,
    DictElement,
    Dictionary,
    FixedValue,
    List,
    Password,
    String,
    TimeMagnitude,
    TimeSpan,
)
from cmk.rulesets.v1.rule_specs import AgentConfig, Topic


def _parameter_form_keystore_bakery() -> Dictionary:
    return Dictionary(
        title=Title("Deploy the Java Keystore certificate monitor plugin"),
        help_text=Help("Deploy the Java Keystore agent plugin to Linux hosts. The plugin monitors certificate expiry in configured JKS and PKCS12 keystores."),
        elements={
            "deploy": DictElement(
                required=True,
                parameter_form=CascadingSingleChoice(
                    title=Title("Deployment options"),
                    help_text=Help("Choose whether to deploy the plugin and at what interval it should run."),
                    elements=[
                        CascadingSingleChoiceElement(
                            name="interval",
                            title=Title("Deploy with execution interval"),
                            parameter_form=TimeSpan(
                                title=Title("Execution interval"),
                                help_text=Help("How often the plugin runs on the monitored host. Certificate checks are inexpensive; an interval of a few hours is typically sufficient."),
                                displayed_magnitudes=[
                                    TimeMagnitude.MINUTE,
                                    TimeMagnitude.HOUR,
                                    TimeMagnitude.DAY,
                                ],
                                prefill=DefaultValue(3600.0),
                            ),
                        ),
                        CascadingSingleChoiceElement(
                            name="nodeploy",
                            title=Title("Do not deploy the plugin"),
                            parameter_form=FixedValue(value=None),
                        ),
                    ],
                ),
            ),
            "keytool": DictElement(
                required=False,
                parameter_form=String(
                    title=Title("Path to keytool binary"),
                    help_text=Help(
                        "Absolute path to the Java keytool binary on the monitored host. "
                        "This is the default for all keystores; individual keystores can override it. "
                        "Leave empty to use /usr/bin/keytool."
                    ),
                    prefill=DefaultValue("/usr/bin/keytool"),
                ),
            ),
            "keystores": DictElement(
                required=True,
                parameter_form=List(
                    title=Title("Keystores to monitor"),
                    help_text=Help("Configure one or more Java keystores (JKS or PKCS12) to monitor. Each entry specifies the keystore path, password, and which aliases to check."),
                    element_template=Dictionary(
                        title=Title("Keystore"),
                        elements={
                            "path": DictElement(
                                required=True,
                                parameter_form=String(
                                    title=Title("Keystore file path"),
                                    help_text=Help("Absolute path to the keystore file on the monitored host (e.g. /opt/app/keystore.jks or /etc/pki/tls/server.p12)."),
                                ),
                            ),
                            "password": DictElement(
                                required=True,
                                parameter_form=Password(
                                    title=Title("Keystore password"),
                                    help_text=Help(
                                        "Password to access the keystore. "
                                        "You can enter the password directly or select a "
                                        "credential from the CheckMK password store. "
                                        "The resolved password is deployed to the monitored "
                                        "host in the agent plugin configuration file."
                                    ),
                                ),
                            ),
                            "aliases": DictElement(
                                required=False,
                                parameter_form=CascadingSingleChoice(
                                    title=Title("Aliases to monitor"),
                                    help_text=Help("Choose which certificate aliases in the keystore to monitor."),
                                    prefill=DefaultValue("all"),
                                    elements=[
                                        CascadingSingleChoiceElement(
                                            name="all",
                                            title=Title("Monitor all certificates"),
                                            parameter_form=FixedValue(value=None),
                                        ),
                                        CascadingSingleChoiceElement(
                                            name="specific",
                                            title=Title("Monitor specific aliases"),
                                            parameter_form=List(
                                                title=Title("Certificate aliases"),
                                                help_text=Help("List of keystore alias names to monitor."),
                                                element_template=String(
                                                    title=Title("Alias name"),
                                                ),
                                            ),
                                        ),
                                    ],
                                ),
                            ),
                            "keytool": DictElement(
                                required=False,
                                parameter_form=String(
                                    title=Title("keytool path override"),
                                    help_text=Help("Override the keytool path for this specific keystore. Leave empty to use the global default."),
                                ),
                            ),
                            "storetype": DictElement(
                                required=False,
                                parameter_form=CascadingSingleChoice(
                                    title=Title("Keystore type"),
                                    help_text=Help("Specify the keystore format. Modern Java (9+) auto-detects the type; only set this for compatibility."),
                                    prefill=DefaultValue("auto"),
                                    elements=[
                                        CascadingSingleChoiceElement(
                                            name="auto",
                                            title=Title("Auto-detect"),
                                            parameter_form=FixedValue(value=None),
                                        ),
                                        CascadingSingleChoiceElement(
                                            name="jks",
                                            title=Title("JKS (Java KeyStore)"),
                                            parameter_form=FixedValue(value=None),
                                        ),
                                        CascadingSingleChoiceElement(
                                            name="pkcs12",
                                            title=Title("PKCS12"),
                                            parameter_form=FixedValue(value=None),
                                        ),
                                    ],
                                ),
                            ),
                        },
                    ),
                ),
            ),
        },
    )


rule_spec_keystore_bakery = AgentConfig(
    title=Title("Java Keystore certificate monitor plugin"),
    name="keystore",
    parameter_form=_parameter_form_keystore_bakery,
    topic=Topic.APPLICATIONS,
    help_text=Help("Deploy the Java Keystore agent plugin for monitoring certificate expiry in JKS and PKCS12 keystores on Linux hosts."),
)
