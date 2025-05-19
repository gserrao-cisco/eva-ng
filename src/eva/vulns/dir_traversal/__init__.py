MODULE_NAME = "dir_traversal"

dir_trav_research_prompt = """
You are an expert vulnerability researcher specializing in directory traversal attacks. 
Your task is to analyze a vulnerability report and extract precise technical details about the directory traversal vulnerability.

Focus on identifying the following crucial elements:

1. ATTACK VECTOR:
   - Which HTTP component contains the traversal sequence? (URL path, query parameter, body parameter, header, cookie, etc.)
   - What is the exact parameter name or header field involved?
   - Is it in a GET, POST, or other HTTP method?

2. TRAVERSAL TECHNIQUE:
   - What specific traversal sequence is being used? (e.g., "../", "..\\", "..%2F", etc.)
   - How many traversal sequences are chained together?
   - Is there any path normalization bypass technique?

3. ENCODING/OBFUSCATION:
   - Is the payload URL-encoded? Double-encoded? Base64-encoded?
   - Are there any special characters or Unicode representations?
   - Is there any filter evasion technique being employed?

4. TARGET:
   - What specific files or directories are being accessed?
   - What operating system is the target running?
   - Are there any server-side technologies mentioned? (PHP, Java, etc.)

5. IMPACT:
   - What sensitive information could be exposed?
   - Is arbitrary file read or write possible?
   - Is it limited to specific directories?


When choosing the vulnerable "uri" make sure that this is the part of the uri that is always required to execute
an attack. Attackers will try to access different resources and the rule must be generic enough to alert on every
attack but specific enough to not block normal traffic. 

Example:

Attacker sends the following url: 
/calendar-toolbox/../resources/../../etc/passwd"

The directory traversal begins after the /calendar-toolbox/ directory, so we consider this the vulnerable uri:

uri: "/calendar-toolbox/"

This makes sure that the following is also blocked:
/calendar-toolbox/../resources/../../etc/shadow"






Here is the vulnerability report:

<report>
{report}
</report>

{format_instructions}

Remember to only extract information explicitly mentioned in the report. If certain details are not provided, indicate "Not specified in report" rather than making assumptions.
"""


from . import agent