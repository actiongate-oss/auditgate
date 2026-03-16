# Copyright 2026 actiongate-oss
# Licensed under the Apache License, Version 2.0;
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the LICENSE file at the
# root of this repository.

"""Enable `python -m auditgate` invocation."""

import sys

from .cli import main

sys.exit(main())
