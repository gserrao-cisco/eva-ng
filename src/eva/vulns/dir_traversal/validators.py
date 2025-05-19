from typing import List

from pydantic import BaseModel, Field

from eva.core.validators import RuleRef


class DirTraversalRule(BaseModel):
    msg: str = Field(alias="Msg", description="A short one sentence description of the vulnerability")
    uri: str = Field(alias="Uri", description="The vulnerable URI")
    vulnparams: List[str] = Field(alias="VulnParams", description="The vulnerable uri parameters")
    rawbuf: bool = Field(alias="RawBuf", default=False,
                         description="False if the vulnerability does not use a common HTTP port")
    dstport: int = Field(alias="DstPort", default=80,
                         description="The destination port for the vulnerability network traffic")
    cookie: bool = Field(alias="Cookie", default=False,
                         description="True if the directory traversal occurs inside the HTTP cookie field")
    header: bool = Field(alias="Header", default=False,
                         description="True if the directory traversal occurs inside an HTTP header field")
    path: bool = Field(alias="Path", default=False,
                       description="True if the directory traversal occurs inside the HTTP URI")
    absolute: bool = Field(alias="Absolute", default=True,
                           description="True if the directory traversal is absolute instead of relative")
    filerule: bool = Field(alias="Filerule", default=False, description="Set to false")
    refs: RuleRef = Field(alias="Refs", description="Vulnerability references")
    sidstart: int = Field(alias="SidStart", default=0, description="Set to 0")
    knownusage: int = Field(alias="KnownUsage", default=1, description="set to 1 if a proof of concept is available")


class DirTraversal(BaseModel):
    generator: str = Field("dir_traversal", alias="Generator")
    rules: DirTraversalRule = Field(alias="Rules")
