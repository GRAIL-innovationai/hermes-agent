"""Tests for skills.create_dir — routing skill_manage create to a durable dir.

When skills.create_dir is set, new skills authored via skill_manage are created
there (flat) instead of the local hub. Deployments whose hub is image-managed
(e.g. GRAIL reconciles $HERMES_HOME/skills/grail every boot) use this to keep
authored skills on a durable, user-owned dir.
"""

import os
from unittest.mock import patch

import pytest


@pytest.fixture
def hermes_home(tmp_path):
    home = tmp_path / ".hermes"
    (home / "skills").mkdir(parents=True)
    return home


def _write_config(home, body):
    (home / "config.yaml").write_text(body)


class TestGetSkillsCreateDir:
    def test_unset_returns_none(self, hermes_home):
        _write_config(hermes_home, "skills:\n  external_dirs: []\n")
        with patch.dict(os.environ, {"HERMES_HOME": str(hermes_home)}):
            from agent.skill_utils import get_skills_create_dir
            assert get_skills_create_dir() is None

    def test_no_skills_block_returns_none(self, hermes_home):
        _write_config(hermes_home, "model:\n  name: x\n")
        with patch.dict(os.environ, {"HERMES_HOME": str(hermes_home)}):
            from agent.skill_utils import get_skills_create_dir
            assert get_skills_create_dir() is None

    def test_absolute_path_returned(self, hermes_home, tmp_path):
        target = tmp_path / "userskills"
        _write_config(hermes_home, f"skills:\n  create_dir: {target}\n")
        with patch.dict(os.environ, {"HERMES_HOME": str(hermes_home)}):
            from agent.skill_utils import get_skills_create_dir
            assert get_skills_create_dir() == target.resolve()

    def test_returned_even_if_not_yet_existing(self, hermes_home, tmp_path):
        target = tmp_path / "does-not-exist-yet"
        _write_config(hermes_home, f"skills:\n  create_dir: {target}\n")
        with patch.dict(os.environ, {"HERMES_HOME": str(hermes_home)}):
            from agent.skill_utils import get_skills_create_dir
            assert get_skills_create_dir() == target.resolve()

    def test_env_var_expanded(self, hermes_home, tmp_path):
        _write_config(hermes_home, "skills:\n  create_dir: ${MY_SKILLS}\n")
        with patch.dict(os.environ, {"HERMES_HOME": str(hermes_home), "MY_SKILLS": str(tmp_path / "ext")}):
            from agent.skill_utils import get_skills_create_dir
            assert get_skills_create_dir() == (tmp_path / "ext").resolve()


class TestResolveSkillDirHonorsCreateDir:
    def test_create_dir_wins_and_is_flat(self, hermes_home, tmp_path):
        target = tmp_path / "userskills"
        _write_config(hermes_home, f"skills:\n  create_dir: {target}\n")
        with patch.dict(os.environ, {"HERMES_HOME": str(hermes_home)}):
            from tools.skill_manager_tool import _resolve_skill_dir
            # category is ignored for placement when create_dir is set (flat)
            assert _resolve_skill_dir("foo", "grail") == target.resolve() / "foo"

    def test_falls_back_to_hub_when_unset(self, hermes_home):
        _write_config(hermes_home, "skills:\n  external_dirs: []\n")
        with patch.dict(os.environ, {"HERMES_HOME": str(hermes_home)}):
            from tools.skill_manager_tool import _resolve_skill_dir, SKILLS_DIR
            assert _resolve_skill_dir("foo") == SKILLS_DIR / "foo"
            assert _resolve_skill_dir("foo", "cat") == SKILLS_DIR / "cat" / "foo"
