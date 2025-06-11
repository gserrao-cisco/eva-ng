import os
import pprint
import subprocess
import sys

from langchain.output_parsers import PydanticOutputParser
from langchain.prompts import PromptTemplate
from langchain.schema.output_parser import StrOutputParser

from eva.core.llm import get_llm
from eva.vulns.dir_traversal.validators import DirTraversal
from eva.vulns.dir_traversal import dir_trav_research_prompt

submit_template = """
You are an expert software vulnerability researcher that analyzes and writes detection content for blocking exploits in firewall products.
The detection content is for the Snort IPS engine.
You are always detail oriented and explain your decisions.
You will be given an external report to analyze.
Your job is to analyze a vulnerability report affecting a piece of software and explain the Snort coverage 
included, how it works, and how it prevents the vulnerability from being exploited by an attacker. 

Here is an external report:
<report>
{report}
</report>

Your job is to write an internal research report in the following format: 

# Thesis
Write a short 1-2 senetence description of the purpose of the report

# Summary
Write an executive summary of the vulnerability and the coverage that was created

# Research
Write a detailed, step by step process of how the vulnerability works. 

# Coverage
Write an explanation of how the Snort rules block the vulnerability
{snort_coverage} 

# External references
{external_urls}

"""
def run(report: str):
    """
    Takes in a report from the research agent and generates coverage for dir traversal
    :param report:
    :return:
    """

    generate_parser = PydanticOutputParser(pydantic_object=DirTraversal)

    generate_prompt = PromptTemplate.from_template(
        template=dir_trav_research_prompt,
        partial_variables={
            "format_instructions": generate_parser.get_format_instructions(),
        },
    )

    generate_chain = generate_prompt | get_llm() | generate_parser
    generate_output = generate_chain.invoke({"report": report})

    pprint.pprint(generate_output.dict())

    with open("./output.json", "w") as fout:
        fout.write(generate_output.json())

    result = subprocess.run([f"{os.getenv('RULESHELL_PATH')}/ruleshell", "output.json"], capture_output=True, text=True)

    if result.returncode == 0:
        print("Command executed successfully!")
        print("Output:")
        print(result.stdout)
    else:
        print("Error:")
        print(result.stderr)
        sys.exit(1)

    submit_parser = StrOutputParser()

    submit_prompt = PromptTemplate.from_template(
        template=submit_template,
    )

    submit_chain = submit_prompt | get_llm() | submit_parser
    submit_output = submit_chain.invoke(
        {
            "report": report,
            "external_urls": sys.argv[1],
            "snort_coverage": result.stdout
        }
    )

    submit_output = submit_output + "\n\n" + result.stdout
    print(submit_output)

    with open("./report.md", "w") as fout:
        fout.write(submit_output)
