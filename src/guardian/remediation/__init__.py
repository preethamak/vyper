"""Auto-remediation sub-package.

Provides automated fix generation for detected Vyper vulnerabilities.
Maps each detector finding to a concrete source-level patch and applies
it to produce a corrected contract.
"""

from guardian.remediation.ast_manipulator import CodePatcher
from guardian.remediation.fix_generator import FixGenerator, FixResult
from guardian.remediation.validator import FixValidator

__all__ = ["CodePatcher", "FixGenerator", "FixResult", "FixValidator"]
