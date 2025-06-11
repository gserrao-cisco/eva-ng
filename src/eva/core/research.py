#TODO maybe break this down into modules

from typing import List
import logging

from langchain.output_parsers import PydanticOutputParser
from langchain_core.prompts import PromptTemplate
from pydantic import BaseModel, Field
from eva.core.react import react_agent_builder
from eva.core.prompts import deep_research_template

log = logging.getLogger("eva")

google_agent_prompt = """

You are an expert software vulnerability researcher. Your jobs includes finding details of software vulnerabilities 
for analysis in order to stop cyber criminals and to protect the public from bad actors.  

Important tips to remember:

1) Proof of concept files are extremely important
2) Use Google search to find all available URLs with proof of concepts for the given vulnerability
3) List all URLs where proof of concepts are available
4) Be specific about where to find the proof of concept code or writeup
5) For each URL that is available, state whether the URL is a description of the vulnerability or if the URL contains
an actual demonstration of the exploit. 
6) Use the web retriever tool to visit promising results and get more information about the research topic

For example: 

Command Injection and Backdoor Account in D-Link NAS Devices
https://github.com/netsecfish/dlink


The vulnerability to research is {vulnerability}

{format_instructions}
"""

class ResearchReference(BaseModel):
    url: str = Field(description="URL of the reference")
    title: str = Field(description="Title of the reference")
    description: str = Field(description="Description of the reference")
    date: str = Field(description="Date of the reference")

class VulnerabilityDetails(BaseModel):
    cve_id: str = Field(description="CVE identifier for the vulnerability")
    product_name: str = Field(description="Name of the affected product")
    vendor_name: str = Field(description="Name of the product vendor")
    vulnerability_class: str = Field(description="Type of vulnerability described in the report")
    protocol: str = Field(description="Network protocol to trigger the vulnerability")
    attack_vector: str = Field(description="Attack vector to trigger the vulnerability")
    cvss_score: str = Field(description="CVSS score of the vulnerability")
    epss_score: str = Field(description="EPSS score of the vulnerability")

class VulnerabilityMechanics(BaseModel):
    summary: str = Field(description="Summary of how the vulnerability is triggered by an attacker")
    example: str = Field(description="Step by step example demonstrating how an attacker exploits the vulnerability")

class ProofOfConcept(BaseModel):
    code: str = Field(description="Proof of concept code demonstrating the vulnerability")
    source: ResearchReference = Field(description="Source of the proof of concept code")

class ResearchNotes(BaseModel):
    vulnerability_mechanics: VulnerabilityMechanics = Field(description="A detailed description of how the vulnerability is triggered")
    proof_of_concept: str = Field(description="Best effort code that generates network traffic to reproduce the vulnerability")
    vulnerable_code_path : str = Field(description="Description of the vulnerable code path if available")
    vulnerable_code_line : str = Field(description="Line number of the vulnerable code if available")
    vulnerable_code_snippet : str = Field(description="Snippet of the vulnerable code if available")

class ResearchReport(BaseModel):
    title: str = Field(description="Title of the report")
    executive_description: str = Field(description="3-5 sentence executive summary")
    research_notes: ResearchNotes = Field(description="Detailed research notes")

    vulnerability_details: VulnerabilityDetails = Field(description="Details of the vulnerability")
    references: list[ResearchReference] = Field(description="List of references")



class SearchResultPocModel(BaseModel):
    url: str = Field(description="the url")
    title: str = Field(description="the title")

class SearchResultWriteupModel(BaseModel):
    url: str = Field(description="the url")
    title: str = Field(description="the title")

class SearchResultModel(BaseModel):
    pocs: List[SearchResultPocModel] = Field(description="List of URLs that contain proof of concept code")
    writeups: List[SearchResultWriteupModel] = Field(description="List of URLs that contain writeups of the vulnerability")
    title: str = Field(description="the title")
    summary: str = Field(description="executive summary of research topic based on search results")


def google_search(vulnerability: str) -> SearchResultModel:
    prompt_template = PromptTemplate(template=google_agent_prompt, input_variables=["vulnerability"])

    parser = PydanticOutputParser(pydantic_object=SearchResultModel)

    agent_executor = react_agent_builder()

    try:
        log.debug("Executing Google search")
        result = agent_executor.invoke(
            input={
                "input": prompt_template.format_prompt(
                    format_instructions=parser.get_format_instructions(),
                    vulnerability=vulnerability)
            },
        )

    except ValueError as e:
        raise e from Exception(f"Error encountered while executing Google search agent.")

    log.debug("Google Agent Results")
    log.debug(result)
    return result['output']

def deep_research(topic, triage_report) -> ResearchReport:

    prompt_template = PromptTemplate(
        template=deep_research_template,
        input_variables=[
            "topic",
            "triage",
        ]
    )

    parser = PydanticOutputParser(pydantic_object=ResearchReport)

    agent_executor = react_agent_builder()

    try:
        log.debug("Executing Eva Deep Research Agent")
        result = agent_executor.invoke(
            input={
                "input": prompt_template.format_prompt(
                    format_instructions=parser.get_format_instructions(),
                    topic=topic,
                    triage=triage_report,
                )
            },
        )

    except ValueError as e:
        raise e from Exception(f"Error encountered while executing Eva Deep Research Agent.")

    log.debug("Eva Deep Research Agent Results")
    log.debug(result)
    return result['output']


def create_research_report(topic: str) -> ResearchReport:
    """Generic cyber‑research agent using Google (via SerpAPI)."""

    # Example return object from the Google search agent
    test_data = {
        "title": "CVE-2024-57727: Path Traversal Vulnerability in SimpleHelp",
        "summary": "CVE-2024-57727 is a critical unauthenticated path traversal vulnerability in the SimpleHelp remote support software (up to v5.5.7). It allows attackers to read arbitrary files from the server, including sensitive files like configuration files and private keys, by sending specially crafted HTTP requests. Proof of concept (PoC) code is publicly available, and exploitation has been demonstrated on both Windows and Linux systems. The vulnerability is widely discussed in security blogs and advisories, with detailed writeups and detection/mitigation strategies. Users are strongly advised to upgrade to SimpleHelp v5.5.8 or later.",
        "pocs": [
            {
                "url": "https://github.com/imjdl/CVE-2024-57727",
                "title": "imjdl/CVE-2024-57727: Python Proof of Concept for SimpleHelp Path Traversal"
            },
            {
                "url": "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-57727.yaml",
                "title": "Nuclei Template for CVE-2024-57727"
            }
        ],
        "writeups": [
            {
                "url": "https://www.offsec.com/blog/cve-2024-57727/",
                "title": "OffSec: Path Traversal Vulnerability in SimpleHelp Web Application"
            },
            {
                "url": "https://medium.com/@unKnOwn37/simplehelp-cve-2024-57727-tryhackme-3bea119c1c1e",
                "title": "Medium: SimpleHelp CVE-2024-57727 TryHackMe Writeup"
            },
            {
                "url": "https://horizon3.ai/attack-research/disclosures/critical-vulnerabilities-in-simplehelp-remote-support-software/",
                "title": "Horizon3.ai: Critical Vulnerabilities in SimpleHelp Remote Support Software"
            }
        ]
    }

    google_results = google_search(topic)
    deep_research_report = deep_research(topic, google_results)
    print(deep_research_report)

    return deep_research_report