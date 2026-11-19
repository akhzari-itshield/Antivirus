"""Curated registry of YARA rule sources (Phase 12 - corrected v1.1.1).

Each source verified against actual GitHub repos with correct:
    - repo path (owner/name)
    - default branch (master or main)
    - subdirs where .yar files live
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class YaraSource:
    key: str
    name: str
    repo: str
    ref: str = "master"
    subdirs: tuple[str, ...] = ("yara",)
    prefix: str = ""
    description: str = ""

    @property
    def effective_prefix(self) -> str:
        return self.prefix or f"{self.key}_"


YARA_SOURCES: List[YaraSource] = [
    YaraSource(
        key="neo23x0",
        name="Florian Roth signature-base",
        repo="neo23x0/signature-base",
        ref="master",
        subdirs=("yara", "malware"),
        description="Frequently updated IOCs and YARA rules. The default source.",
    ),
    YaraSource(
        key="elastic",
        name="Elastic Security",
        repo="elastic/protections-artifacts",
        ref="main",
        subdirs=("yara",),  # protections-artifacts has a yara/ directory
        description="1,000+ YARA rules from Elastic Endpoint.",
    ),
    YaraSource(
        key="reversinglabs",
        name="ReversingLabs",
        repo="reversinglabs/reversinglabs-yara-rules",
        ref="main",
        subdirs=("YARA",),  # capital YARA directory
        description="Exploits, infostealers, ransomware, trojans.",
    ),
    YaraSource(
        key="inquest",
        name="InQuest",
        repo="InQuest/yara-rules",
        ref="master",
        subdirs=("rules",),  # rules/ subdirectory
        description="Threat hunting rules from InQuest researchers.",
    ),
    YaraSource(
        key="bartblaze",
        name="bartblaze",
        repo="bartblaze/Yara-rules",
        ref="master",
        subdirs=("",),  # rules at root
        description="Personal collection, APT and malware families.",
    ),
    YaraSource(
        key="deadbits",
        name="Deadbits (archived)",
        repo="deadbits/yara-rules",
        ref="master",
        subdirs=("rules",),  # rules/ subdirectory
        description="Collection by Adam Swanda. Archived but still accessible.",
    ),
    YaraSource(
        key="didierstevens",
        name="Didier Stevens",
        repo="DidierStevens/Yara",
        ref="master",
        subdirs=("",),  # rules at root
        description="Hunting-focused rules from Didier Stevens.",
    ),
    YaraSource(
        key="strangereal",
        name="StrangeRealIntel",
        repo="strangerealintel/StrangerealIntel",
        ref="main",
        subdirs=("yara",),
        description="Regularly updated rules covering fresh threats.",
    ),
    YaraSource(
        key="jeff0falltrades",
        name="jeFF0Falltrades",
        repo="jeFF0Falltrades/jeFF0Falltrades-yara",
        ref="main",
        subdirs=("yara",),
        description="YARA signatures for various malware families.",
    ),
    YaraSource(
        key="yaraforge",
        name="YARA Forge",
        repo="YARARules/YaraForge",
        ref="main",
        subdirs=("yara",),
        description="High-quality YARA rule packages.",
    ),
    YaraSource(
        key="eset",
        name="ESET IOCs",
        repo="eset/malware-ioc",
        ref="master",
        subdirs=("yara",),
        description="YARA rules from ESET researchers.",
    ),
    YaraSource(
        key="mcafee",
        name="McAfee ATR",
        repo="advanced-threat-research/yara-rules",
        ref="master",
        subdirs=("",),  # rules at root
        description="YARA rules from McAfee Advanced Threat Research.",
    ),
]


_SOURCE_MAP: Dict[str, YaraSource] = {s.key: s for s in YARA_SOURCES}


def get_source(key: str) -> Optional[YaraSource]:
    return _SOURCE_MAP.get(key)


def list_sources() -> List[YaraSource]:
    return list(YARA_SOURCES)


def sources_summary() -> List[dict]:
    return [
        {
            "key": s.key, "name": s.name, "repo": s.repo, "ref": s.ref,
            "description": s.description, "subdirs": list(s.subdirs),
            "prefix": s.effective_prefix,
        }
        for s in YARA_SOURCES
    ]
