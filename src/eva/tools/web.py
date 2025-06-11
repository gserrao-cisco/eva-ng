import bs4
import httpx
from langchain.tools import Tool


def get_web_resource(url: str):
    """
    Fetches the content of a web page and returns its text using bs4.
    :param url: url to fetch
    :return:
    """
    response = httpx.get(url, timeout=120)
    if response.status_code != 200:
        return "<unable to retrieve web results, no content available>"


    soup = bs4.BeautifulSoup(response.text, 'html.parser')
    return soup.get_text()


get_web_resource_tool = Tool(
    name="web_page_retriever",
    func=get_web_resource,
    description="Useful for fetching a web resource using the url"
)