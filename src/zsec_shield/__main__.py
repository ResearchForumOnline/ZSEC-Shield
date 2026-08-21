from __future__ import annotations

import multiprocessing

from zsec_shield.cli import entrypoint

if __name__ == "__main__":
    multiprocessing.freeze_support()
    entrypoint()
