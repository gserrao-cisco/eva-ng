from enum import Enum
from typing import List

from pydantic import BaseModel, Field


class RuleGeneratorsEnum(str, Enum):
    cmd_injection = 'cmd_injection'
    dir_traversal = 'dir_traversal'


class RuleRef(BaseModel):
    url: str = Field(alias="Url", default="", description="A URL hosting a description of the vulnerability (optional)")
    cve: str = Field(alias="Cve", default="", description="The CVE ID matching the vulnerability (optional)")


class CmdInjectionRule(BaseModel):
    msg: str = Field(alias="Msg", description="A short one sentence description of the vulnerability")
    uri: str = Field(alias="Uri", description="The vulnerable URI")
    vulnparams: List[str] = Field(alias="VulnParams", description="The vulnerable parameters")
    url: bool = Field(alias="Url", default=True, description="True if the vulnerability uses HTTP")
    rawbuf: bool = Field(alias="RawBuf", default=False,
                         description="False if the vulnerability does not use a common HTTP port")
    dstport: int = Field(alias="DstPort", default=80,
                         description="The destination port for the vulnerability network traffic")
    filerule: bool = Field(alias="Filerule", default=False, description="Set to false")
    refs: RuleRef = Field(alias="Refs", description="Vulnerability references")
    sidstart: int = Field(alias="SidStart", default=0, description="Set to 0")


class CmdInjection(BaseModel):
    generator: str = Field("cmd_injection", alias="Generator")
    rules: CmdInjectionRule = Field(alias="Rules")


"""
{
   "Generator": "cmd_injection",
   "Rules": {
      "Msg": "GENERATED",
      "Uri": "/uapi-cgi/viewer/testaction.cgi",
      "Vulnparams": [
         "ip"
      ],
      "URL": false,
      "RawBuf": false,
      "DstPort": 80,
      "Filerule": false,
      "Refs": {
         "Url": "",
         "Cve": null
      },
      "SidStart": 0
   }
}
"""



"""
{
   "Generator": "dir_traversal",
   "Rules": {
      "Msg": "msg",
      "Uri": "",
      "Vulnparams": [
         "param"
      ],
      "RawBuf": false,
      "DstPort": 0,
      "Cookie": false,
      "Header": false,
      "Path": false,
      "Absolute": true,
      "Filerule": false,
      "Refs": {
         "Cves": null,
         "Urls": null
      },
      "SidStart": 0,
      "KnownUsage": 2
   }
}
"""


class AttackVector(str, Enum):
    local = 'local'
    network = 'network'
    other = 'other'


class VulnClass(str, Enum):
    cmd_injection = 'command injection'
    dir_traversal = 'directory traversal'
    sql_injection = 'sql injection'
    other = 'other'


class TriageValidator(BaseModel):
    cve_id: str = Field(description="CVE identifier for the vulnerability")
    product_name: str = Field(description="name of the affected product")
    product_vendor_name: str = Field(description="name of the product vendor")
    product_version: str = Field(description="version of the affected product ex. v1.2.1")
    vulnerability_class: VulnClass = Field(description="the type of vulnerability described in the report")
    protocol: str = Field(description="the network protocol to trigger the vulnerability")
    attack_vector: AttackVector = Field(description="the attack vector to trigger the vulnerability")
    rule_generator: RuleGeneratorsEnum = Field(
        description="the rule generator to use if the vulnerability class matches a known generator")
