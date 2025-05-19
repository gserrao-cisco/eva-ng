import os
import pprint
import subprocess
import sys
import re

from eva.tools.nist import cve_lookup
from rich.console import Console
import rich

import typer
from langchain.output_parsers import PydanticOutputParser
from langchain.prompts import PromptTemplate
from langchain.schema.output_parser import StrOutputParser
from typer import Typer
from typing_extensions import Annotated

from eva.core.research import create_research_report
from eva.core.llm import get_llm
from eva.core.prompts import triage_template
from eva.core.validators import RuleGeneratorsEnum
from eva.core.validators import TriageValidator
from eva.tools.web import get_web_resource
from eva.core.research import ResearchReport
from eva import modules
import logging

log = logging.getLogger("eva")

generate_app = typer.Typer(context_settings={"help_option_names": ["-h", "--help"]}, no_args_is_help=True)

def triage(report: ResearchReport) -> TriageValidator:
    triage_parser = PydanticOutputParser(pydantic_object=TriageValidator)

    triage_prompt = PromptTemplate.from_template(
        template=triage_template,
        partial_variables={
            "format_instructions": triage_parser.get_format_instructions(),
            "generators_available": [g for g in RuleGeneratorsEnum]
        },
    )

    model = get_llm()

    triage_chain = triage_prompt | model | triage_parser

    triage_output = triage_chain.invoke({"report": report})

    return triage_output

@generate_app.command()
def rules(topic: Annotated[str, typer.Argument(help="Vulnerability topic")]):

    # Create research report
    research_report = create_research_report(topic)

    triage_output = triage(research_report)
    pprint.pprint(triage_output.model_dump())

    if not triage_output.rule_generator:
        print(f"No supported rule generator found for this vulnerability type.")
        sys.exit(0)

    print(f"Found a supported rule generator for this vuln: {triage_output.rule_generator}")

    # Find correct module that supports this rule generator
    rules_module = modules.get(triage_output.rule_generator, None)

    if not rules_module:
        print(f"Module for rule generator {triage_output.rule_generator} not found.")
        sys.exit(1)

    print(f"Using module {rules_module} for rule generator {triage_output.rule_generator}")

    # Write
    rules_module.agent.run(research_report)


@generate_app.command()
def research(topic: Annotated[str, typer.Argument(help="Vulnerability CVE or URL")]):
    """
    Research a vulnerability and generate a report
    """

    console = Console()
    log.debug(f"Generating research report for {topic}")
    report = create_research_report(topic)

    console.print("Report")

    print(report)