import logging
import os

from langchain.tools import Tool
from serpapi import GoogleSearch

log = logging.getLogger("eva")


def get_search_result_serpapi(text: str) -> str:
    """
    Search Google for information about a software product or vendor
    """
    search = GoogleSearch({
        "q": text,
        "api_key": os.environ["SERPAPI_API_KEY"]
    }
    )
    return search.get_dict()["organic_results"]


google_search_tool = Tool(
    name="google_search",
    func=get_search_result_serpapi,
    description="Execute Google searches, useful for finding information about security vulnerabilities"
)
