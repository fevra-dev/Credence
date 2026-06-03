"""
Git repository dumper and reconstructor.

Downloads exposed .git directories and reconstructs the full repository.
"""

import asyncio
import logging
import re
import zlib
from pathlib import Path
from typing import Dict, List, Set

import aiofiles
import aiohttp

logger = logging.getLogger(__name__)


class GitDumper:
    """Dump and reconstruct exposed .git repositories"""

    def __init__(
        self,
        base_url: str,
        output_dir: Path,
        session: aiohttp.ClientSession,
        max_workers: int = 10
    ):
        self.base_url = base_url.rstrip('/')
        self.output_dir = Path(output_dir)
        self.session = session
        self.max_workers = max_workers
        self.downloaded: Set[str] = set()
        self.queue: asyncio.Queue = asyncio.Queue()
        self.failed: List[str] = []

    async def dump(self) -> Dict:
        """
        Main dump orchestrator.
        
        Returns:
            Dict with results including success status, files downloaded, etc.
        """
        logger.info(f"Starting git dump for {self.base_url}")

        results = {
            'success': False,
            'files_downloaded': 0,
            'files_failed': 0,
            'objects_found': 0,
            'branches': [],
            'commits': [],
            'repository_reconstructed': False
        }

        # Create .git directory
        git_dir = self.output_dir / '.git'
        git_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Step 1: Download core files
            logger.info("Downloading core git files...")
            await self._download_core_files()

            # Step 2: Parse refs and index for object hashes
            logger.info("Parsing refs and index...")
            await self._parse_packed_refs()
            await self._parse_index()
            await self._parse_refs()

            # Step 3: Download all objects
            logger.info("Downloading git objects...")
            await self._download_objects()

            # Step 4: Try to reconstruct the repository
            logger.info("Reconstructing repository...")
            reconstruction_success = await self._reconstruct_repo()

            results['success'] = len(self.downloaded) > 0
            results['files_downloaded'] = len(self.downloaded)
            results['files_failed'] = len(self.failed)
            results['repository_reconstructed'] = reconstruction_success

            logger.info(
                f"Git dump complete: {results['files_downloaded']} files downloaded, "
                f"{results['files_failed']} failed"
            )

        except Exception as e:
            logger.error(f"Git dump failed: {e}")
            results['error'] = str(e)

        return results

    async def _download_core_files(self):
        """Download essential .git files"""
        core_files = [
            'HEAD',
            'config',
            'description',
            'index',
            'packed-refs',
            'info/refs',
            'info/exclude',
            'logs/HEAD',
            'logs/refs/heads/main',
            'logs/refs/heads/master',
            'logs/refs/remotes/origin/HEAD',
            'logs/refs/remotes/origin/main',
            'logs/refs/remotes/origin/master',
            'refs/heads/main',
            'refs/heads/master',
            'refs/remotes/origin/HEAD',
            'refs/remotes/origin/main',
            'refs/remotes/origin/master',
            'refs/stash',
        ]

        tasks = []
        for file_path in core_files:
            url = f"{self.base_url}/.git/{file_path}"
            local_path = self.output_dir / '.git' / file_path
            tasks.append(self._download_file(url, local_path, file_path))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _download_file(
        self,
        url: str,
        local_path: Path,
        identifier: str
    ) -> bool:
        """Download a single file"""
        if identifier in self.downloaded:
            return False

        try:
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    local_path.parent.mkdir(parents=True, exist_ok=True)
                    content = await resp.read()

                    async with aiofiles.open(local_path, 'wb') as f:
                        await f.write(content)

                    self.downloaded.add(identifier)
                    logger.debug(f"Downloaded: {identifier}")
                    return True
                elif resp.status == 404:
                    logger.debug(f"Not found: {identifier}")
                else:
                    logger.debug(f"Failed {resp.status}: {identifier}")

        except asyncio.TimeoutError:
            logger.debug(f"Timeout: {identifier}")
        except Exception as e:
            logger.debug(f"Error downloading {identifier}: {e}")

        self.failed.append(identifier)
        return False

    async def _parse_index(self):
        """Parse .git/index file for object references"""
        index_path = self.output_dir / '.git' / 'index'
        if not index_path.exists():
            return

        try:
            async with aiofiles.open(index_path, 'rb') as f:
                content = await f.read()

            # Git index contains SHA-1 hashes in binary form
            # Look for 40-char hex patterns and 20-byte binary SHAs
            hex_pattern = rb'[a-f0-9]{40}'
            for match in re.finditer(hex_pattern, content):
                sha = match.group().decode()
                await self.queue.put(f"objects/{sha[:2]}/{sha[2:]}")

        except Exception as e:
            logger.debug(f"Failed to parse index: {e}")

    async def _parse_packed_refs(self):
        """Parse packed-refs file"""
        packed_refs = self.output_dir / '.git' / 'packed-refs'
        if not packed_refs.exists():
            return

        try:
            async with aiofiles.open(packed_refs, 'r') as f:
                content = await f.read()

            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('#') or not line:
                    continue

                parts = line.split()
                if len(parts) >= 1:
                    sha = parts[0]
                    if re.match(r'^[a-f0-9]{40}$', sha):
                        await self.queue.put(f"objects/{sha[:2]}/{sha[2:]}")

        except Exception as e:
            logger.debug(f"Failed to parse packed-refs: {e}")

    async def _parse_refs(self):
        """Parse ref files for object hashes"""
        refs_dir = self.output_dir / '.git' / 'refs'
        if not refs_dir.exists():
            return

        try:
            for ref_file in refs_dir.rglob('*'):
                if ref_file.is_file():
                    async with aiofiles.open(ref_file, 'r') as f:
                        content = await f.read()

                    sha = content.strip()
                    if re.match(r'^[a-f0-9]{40}$', sha):
                        await self.queue.put(f"objects/{sha[:2]}/{sha[2:]}")

        except Exception as e:
            logger.debug(f"Failed to parse refs: {e}")

    async def _download_objects(self):
        """Download all git objects using worker pool"""
        workers = []
        for _ in range(self.max_workers):
            workers.append(asyncio.create_task(self._object_worker()))

        # Wait for queue to be processed
        await self.queue.join()

        # Cancel workers
        for worker in workers:
            worker.cancel()

        # Wait for workers to finish
        await asyncio.gather(*workers, return_exceptions=True)

    async def _object_worker(self):
        """Worker that downloads objects from queue"""
        while True:
            try:
                obj_path = await self.queue.get()

                url = f"{self.base_url}/.git/{obj_path}"
                local_path = self.output_dir / '.git' / obj_path

                success = await self._download_file(url, local_path, obj_path)

                if success:
                    # Parse object for more references
                    await self._parse_object(local_path)

                self.queue.task_done()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Object worker error: {e}")
                self.queue.task_done()

    async def _parse_object(self, obj_path: Path):
        """Parse git object for more SHA references"""
        try:
            async with aiofiles.open(obj_path, 'rb') as f:
                compressed = await f.read()

            # Decompress git object
            try:
                decompressed = zlib.decompress(compressed)
            except zlib.error:
                return

            # Find SHA-1 references in the object
            hex_pattern = rb'[a-f0-9]{40}'
            for match in re.finditer(hex_pattern, decompressed):
                sha = match.group().decode()
                obj_ref = f"objects/{sha[:2]}/{sha[2:]}"

                # Only add if not already downloaded/queued
                if obj_ref not in self.downloaded:
                    await self.queue.put(obj_ref)

        except Exception as e:
            logger.debug(f"Failed to parse object {obj_path}: {e}")

    async def _reconstruct_repo(self) -> bool:
        """Attempt to reconstruct working directory from .git"""
        try:
            import subprocess

            result = subprocess.run(
                ['git', 'checkout', '--force', '.'],
                cwd=str(self.output_dir),
                capture_output=True,
                timeout=30
            )

            if result.returncode == 0:
                logger.info("Repository reconstructed successfully")
                return True
            else:
                logger.warning(f"Git checkout failed: {result.stderr.decode()}")
                return False

        except subprocess.TimeoutExpired:
            logger.warning("Git checkout timed out")
            return False
        except FileNotFoundError:
            logger.warning("Git command not found - cannot reconstruct repository")
            return False
        except Exception as e:
            logger.warning(f"Repository reconstruction failed: {e}")
            return False
