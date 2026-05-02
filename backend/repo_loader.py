"""Resolve a CLI target (GitHub URL or local path) to a local directory."""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


class RepoLoader:
    """Load a target repo from a GitHub URL or local path.

    Usage:
        loader = RepoLoader("https://github.com/foo/bar")
        with loader as path:
            # path is a local directory
            ...
        # cleanup happens automatically on __exit__
    """

    def __init__(self, source: str, no_cleanup: bool = False) -> None:
        self.source = source
        self.no_cleanup = no_cleanup
        self._tmp_dir: str | None = None
        self.local_path: str = ""

    def __enter__(self) -> str:
        self.local_path = self._resolve()
        return self.local_path

    def __exit__(self, *_) -> None:
        self.cleanup()

    def _resolve(self) -> str:
        if self._looks_like_github_url(self.source):
            return self._clone_github()
        path = Path(self.source).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Local path does not exist: {self.source}")
        if not path.is_dir():
            raise NotADirectoryError(f"Expected a directory, got: {self.source}")
        logger.info("Using local path: %s", path)
        return str(path)

    @staticmethod
    def _looks_like_github_url(s: str) -> bool:
        return s.startswith(("https://github.com/", "git@github.com:", "http://github.com/"))

    def _clone_github(self) -> str:
        self._tmp_dir = tempfile.mkdtemp(prefix="vuln-repo-")
        url = self.source
        # Normalize SSH URL to HTTPS
        if url.startswith("git@github.com:"):
            url = "https://github.com/" + url[len("git@github.com:"):]
        # Strip trailing .git
        url = url.rstrip("/")
        if not url.endswith(".git"):
            url += ".git"

        logger.info("Cloning %s into %s", url, self._tmp_dir)
        result = subprocess.run(
            ["git", "clone", "--depth=1", url, self._tmp_dir],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            shutil.rmtree(self._tmp_dir, ignore_errors=True)
            self._tmp_dir = None
            raise RuntimeError(
                f"git clone failed (exit {result.returncode}):\n{result.stderr}"
            )
        logger.info("Clone complete: %s", self._tmp_dir)
        return self._tmp_dir

    def cleanup(self) -> None:
        if self._tmp_dir and not self.no_cleanup:
            logger.info("Cleaning up cloned repo: %s", self._tmp_dir)
            shutil.rmtree(self._tmp_dir, ignore_errors=True)
            self._tmp_dir = None
