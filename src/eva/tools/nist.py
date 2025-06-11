import httpx
from langchain.tools import Tool


def cve_lookup(cve_id: str) -> dict:
    """
    Lookup a CVE ID using the NIST NVD API.
    """

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id.upper()}"

    response = httpx.get(url)
    if response.status_code != 200:
        raise ValueError(f"Failed to fetch data for CVE ID {cve_id}: {response.status_code}")

    return response.json()


nist_cve_lookup_tool = Tool(
    name="nist_cve_lookup_tool",
    func=cve_lookup,
    description="Useful for collecting up to date information about a given CVE from NIST"
)
