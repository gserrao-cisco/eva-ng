import logging
import os
from typing import List
from langchain import hub
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain.tools import Tool

from eva.core.llm import get_llm
from eva.tools.web import get_web_resource_tool
from eva.tools.google import google_search_tool
from eva.tools.nist import nist_cve_lookup_tool
from typing import Optional

# workaround for Cisco langsmith not having the prompt we want
import pickle

def react_agent_builder(additional_tools: List[Tool] = None):

    if os.getenv("LANGCHAIN_TRACING_V2", None):
        with open("./hwchase_17_openai_tools_agent.pkl", "rb") as f:
            react_prompt = pickle.load(f)
    else:
        react_prompt = hub.pull("hwchase17/openai-tools-agent")

    tools_for_agent = [
        get_web_resource_tool,
        google_search_tool,
        nist_cve_lookup_tool,
    ]

    if additional_tools:
        for tool in additional_tools:
            tools_for_agent.append(tool)

    agent = create_openai_tools_agent(llm=get_llm(), prompt=react_prompt, tools=tools_for_agent)

    agent_executor = AgentExecutor(agent=agent,
                                   tools=tools_for_agent,
                                   return_intermediate_steps=True,
                                   handle_parsing_errors=True,
                                   verbose=True if logging.getLogger("eva").level == logging.DEBUG else False)


    return agent_executor