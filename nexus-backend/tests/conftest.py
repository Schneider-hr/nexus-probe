import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Keep tests in-memory regardless of the developer's environment: an empty
# NEXUS_DB_PATH means "do not persist". Must be set before nexus_backend.api is imported.
os.environ["NEXUS_DB_PATH"] = ""
