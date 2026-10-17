"""Only bootstrap installed SDK; the original entry is executed by the product runner."""
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(os.environ["AGF_ZERO_CODE_SDK_ROOT"]) / "python"))
from agf_agentteams.bootstrap import main

raise SystemExit(main())
