"""GuardX Skills - Modular security knowledge base.

Each skill is a self-contained module that teaches the AI agent
how to detect, exploit, and fix a specific type of vulnerability.

Skills are auto-discovered at startup. To add a new skill,
create a .py file in this directory following the template.
"""
import os
import importlib
import pkgutil

_skills_registry = {}


def load_all_skills() -> dict:
    """Auto-discover and load all skill modules."""
    skills_dir = os.path.dirname(__file__)
    for _, name, _ in pkgutil.iter_modules([skills_dir]):
        if name.startswith("_"):
            continue
        mod = importlib.import_module(f"guardx.skills.{name}")
        if hasattr(mod, "SKILL"):
            _skills_registry[mod.SKILL["id"]] = mod.SKILL
    return _skills_registry


def get_all_skills() -> dict:
    if not _skills_registry:
        load_all_skills()
    return _skills_registry


def get_skill(skill_id: str):
    return get_all_skills().get(skill_id)


def get_skills_prompt() -> str:
    """Generate prompt injection with all skills knowledge for the AI agent."""
    skills = get_all_skills()
    if not skills:
        return ""

    lines = ["## SECURITY SKILLS KNOWLEDGE BASE\n"]
    for sid, skill in skills.items():
        lines.append(f"### {skill['name']} [{skill['severity']}]")
        lines.append(f"Category: {skill['category']}")
        lines.append(f"\nDetection:\n{skill['detection']}")
        lines.append(f"\nExploitation:\n{skill['exploitation']}")
        lines.append(f"\nRemediation:\n{skill['remediation']}")
        lines.append(f"\nTools: {', '.join(skill['tools'])}")

        # Include payloads if available
        payloads = skill.get("payloads", [])
        if payloads:
            lines.append(f"\nPayloads:\n" + "\n".join(f"  - {p}" for p in payloads))

        # Include references if available
        references = skill.get("references", [])
        if references:
            lines.append(f"\nReferences: {' | '.join(references)}")

        lines.append("")
    return "\n".join(lines)
