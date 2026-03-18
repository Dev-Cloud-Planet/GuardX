"""
GuardX Plugin System
Allows users to add custom tools and skills without modifying core code.

Plugins are stored in ~/.guardx/plugins/ and discovered at startup.
Each plugin is a directory with a manifest.json and tool/skill .py files.
"""

import os
import sys
import json
import shutil
import importlib.util
from typing import Dict, List, Optional, Any
from pathlib import Path


class PluginManager:
    """Manages loading, installing, and managing GuardX plugins."""

    def __init__(self, plugins_dir: Optional[str] = None):
        """Initialize plugin manager.

        Args:
            plugins_dir: Directory where plugins are stored. Defaults to ~/.guardx/plugins/
        """
        if plugins_dir is None:
            plugins_dir = os.path.expanduser("~/.guardx/plugins/")

        self.plugins_dir = Path(plugins_dir)
        self.plugins_dir.mkdir(parents=True, exist_ok=True)

        # Cache for loaded plugins
        self._loaded_plugins: Dict[str, dict] = {}
        self._tools: Dict[str, dict] = {}
        self._skills: Dict[str, dict] = {}

    def discover_plugins(self) -> List[str]:
        """Scan plugins directory and return list of plugin names.

        Returns:
            List of installed plugin directory names
        """
        if not self.plugins_dir.exists():
            return []

        plugins = []
        for item in self.plugins_dir.iterdir():
            if item.is_dir() and not item.name.startswith("_"):
                manifest_path = item / "manifest.json"
                if manifest_path.exists():
                    plugins.append(item.name)

        return sorted(plugins)

    def _load_manifest(self, plugin_name: str) -> dict:
        """Load and parse manifest.json for a plugin.

        Args:
            plugin_name: Name of the plugin (directory name)

        Returns:
            Dictionary with manifest contents

        Raises:
            FileNotFoundError: If manifest doesn't exist
            json.JSONDecodeError: If manifest is invalid JSON
        """
        manifest_path = self.plugins_dir / plugin_name / "manifest.json"

        if not manifest_path.exists():
            raise FileNotFoundError(f"Manifest not found for plugin: {plugin_name}")

        with open(manifest_path, "r") as f:
            return json.load(f)

    def _load_tool_from_file(self, plugin_dir: Path, tool_file: str) -> Optional[dict]:
        """Load a tool from a Python file.

        Args:
            plugin_dir: Path to plugin directory
            tool_file: Name of the tool .py file (e.g., 'my_tool.py')

        Returns:
            Tool schema dict if found, None otherwise
        """
        tool_path = plugin_dir / tool_file

        if not tool_path.exists():
            return None

        # Dynamically import the module
        spec = importlib.util.spec_from_file_location(
            f"plugin_tool_{tool_file[:-3]}",
            str(tool_path)
        )
        if spec is None or spec.loader is None:
            return None

        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module

        try:
            spec.loader.exec_module(module)
            if hasattr(module, "TOOL_SCHEMA") and hasattr(module, "execute"):
                return {
                    "schema": module.TOOL_SCHEMA,
                    "execute": module.execute,
                    "is_available": getattr(module, "is_available", lambda: True),
                }
        except Exception as e:
            print(f"Error loading tool {tool_file} from plugin {plugin_dir.name}: {e}")

        return None

    def _load_skill_from_file(self, plugin_dir: Path, skill_file: str) -> Optional[dict]:
        """Load a skill from a Python file.

        Args:
            plugin_dir: Path to plugin directory
            skill_file: Name of the skill .py file (e.g., 'my_skill.py')

        Returns:
            Skill dict if found, None otherwise
        """
        skill_path = plugin_dir / skill_file

        if not skill_path.exists():
            return None

        # Dynamically import the module
        spec = importlib.util.spec_from_file_location(
            f"plugin_skill_{skill_file[:-3]}",
            str(skill_path)
        )
        if spec is None or spec.loader is None:
            return None

        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module

        try:
            spec.loader.exec_module(module)
            if hasattr(module, "SKILL"):
                return module.SKILL
        except Exception as e:
            print(f"Error loading skill {skill_file} from plugin {plugin_dir.name}: {e}")

        return None

    def load_plugin(self, plugin_name: str) -> dict:
        """Load a single plugin by name.

        Args:
            plugin_name: Name of the plugin (directory name)

        Returns:
            Dictionary with keys "manifest", "tools", and "skills"

        Raises:
            FileNotFoundError: If plugin directory or manifest not found
        """
        plugin_dir = self.plugins_dir / plugin_name

        if not plugin_dir.exists():
            raise FileNotFoundError(f"Plugin directory not found: {plugin_name}")

        if plugin_name in self._loaded_plugins:
            return self._loaded_plugins[plugin_name]

        manifest = self._load_manifest(plugin_name)

        tools = []
        for tool_file in manifest.get("tools", []):
            tool = self._load_tool_from_file(plugin_dir, tool_file)
            if tool:
                tools.append(tool)

        skills = []
        for skill_file in manifest.get("skills", []):
            skill = self._load_skill_from_file(plugin_dir, skill_file)
            if skill:
                skills.append(skill)

        result = {
            "manifest": manifest,
            "tools": tools,
            "skills": skills,
        }

        self._loaded_plugins[plugin_name] = result
        return result

    def load_all(self) -> dict:
        """Load all installed plugins.

        Returns:
            Dictionary with keys "tools" and "skills" containing all loaded plugins' items
        """
        plugins = self.discover_plugins()
        all_tools = []
        all_skills = []

        for plugin_name in plugins:
            try:
                plugin = self.load_plugin(plugin_name)
                all_tools.extend(plugin["tools"])
                all_skills.extend(plugin["skills"])
            except Exception as e:
                print(f"Failed to load plugin {plugin_name}: {e}")

        return {
            "tools": all_tools,
            "skills": all_skills,
        }

    def install_plugin(self, path_or_url: str) -> bool:
        """Install a plugin from a local path or URL.

        Args:
            path_or_url: Local filesystem path to plugin directory

        Returns:
            True if successful, False otherwise
        """
        source_path = Path(path_or_url)

        if not source_path.exists() or not source_path.is_dir():
            print(f"Plugin source not found: {path_or_url}")
            return False

        manifest_path = source_path / "manifest.json"
        if not manifest_path.exists():
            print(f"No manifest.json found in plugin: {path_or_url}")
            return False

        try:
            with open(manifest_path, "r") as f:
                manifest = json.load(f)

            plugin_name = manifest.get("name")
            if not plugin_name:
                print("Plugin manifest must contain 'name' field")
                return False

            dest_path = self.plugins_dir / plugin_name

            # Remove existing plugin if present
            if dest_path.exists():
                shutil.rmtree(dest_path)

            # Copy entire plugin directory
            shutil.copytree(source_path, dest_path)

            # Clear cached version if any
            if plugin_name in self._loaded_plugins:
                del self._loaded_plugins[plugin_name]

            return True

        except Exception as e:
            print(f"Failed to install plugin: {e}")
            return False

    def remove_plugin(self, plugin_name: str) -> bool:
        """Remove an installed plugin.

        Args:
            plugin_name: Name of the plugin to remove

        Returns:
            True if successful, False otherwise
        """
        plugin_dir = self.plugins_dir / plugin_name

        if not plugin_dir.exists():
            print(f"Plugin not found: {plugin_name}")
            return False

        try:
            shutil.rmtree(plugin_dir)

            # Clear cache
            if plugin_name in self._loaded_plugins:
                del self._loaded_plugins[plugin_name]

            return True
        except Exception as e:
            print(f"Failed to remove plugin {plugin_name}: {e}")
            return False

    def list_plugins(self) -> List[dict]:
        """List all installed plugins with metadata.

        Returns:
            List of dictionaries with plugin metadata (name, version, author, description)
        """
        plugins = []

        for plugin_name in self.discover_plugins():
            try:
                manifest = self._load_manifest(plugin_name)
                plugins.append({
                    "name": manifest.get("name"),
                    "version": manifest.get("version", "1.0.0"),
                    "author": manifest.get("author", "Unknown"),
                    "description": manifest.get("description", ""),
                })
            except Exception as e:
                print(f"Error listing plugin {plugin_name}: {e}")

        return plugins

    def get_plugin_tools(self, plugin_name: str) -> List[dict]:
        """Get tool schemas from a plugin.

        Args:
            plugin_name: Name of the plugin

        Returns:
            List of tool schema dictionaries
        """
        try:
            plugin = self.load_plugin(plugin_name)
            return [tool["schema"] for tool in plugin["tools"]]
        except Exception as e:
            print(f"Failed to get tools from plugin {plugin_name}: {e}")
            return []

    def get_plugin_skills(self, plugin_name: str) -> List[dict]:
        """Get skill dictionaries from a plugin.

        Args:
            plugin_name: Name of the plugin

        Returns:
            List of skill dictionaries
        """
        try:
            plugin = self.load_plugin(plugin_name)
            return plugin["skills"]
        except Exception as e:
            print(f"Failed to get skills from plugin {plugin_name}: {e}")
            return []


# Global singleton instance
_plugin_manager = None


def get_plugin_manager(plugins_dir: Optional[str] = None) -> PluginManager:
    """Get or create global plugin manager instance.

    Args:
        plugins_dir: Directory where plugins are stored

    Returns:
        PluginManager instance
    """
    global _plugin_manager
    if _plugin_manager is None:
        _plugin_manager = PluginManager(plugins_dir)
    return _plugin_manager
