from abc import ABC, abstractmethod
from typing import Optional
from patchguard.domain.models import AttackEvents, RequestPayload, PatchResult

class BaseDetectorPort(ABC):
    """
    1. Base interface for all detectors in the system.
    2. IT TAKE THE INCOMING REQUEST PAYLOAD AND EVALUATE IT AGAINST THE DETECTOR'S RULES.
    3. IF A THREAT IS DETECTED, IT RETURNS AN AttackEvents OBJECT AND BLOCKS THE REQUEST. 
    4. IF NO THREAT IS DETECTED, IT RETURNS None AND ALLOWS THE REQUEST TO PROCEED.
    """

    @property
    @abstractmethod
    def threat_type(self) -> str:
        """Return the type of threat this detector handles."""
        pass
   
   
    @abstractmethod
    def detect(self, payload: RequestPayload) -> Optional[AttackEvents]:
        """Detect potential threats in the given payload."""
        pass

class RemediationEnginePort(ABC):
    """
    1. Base interface for the remediation engine.
    2. IT TAKES ATTACK EVENT FROM THE DETACTOR AND ASKS LLM TO SYNTHESIZE A PATCH FOR THE VULNERABILITY.
    3. IT RETURNS A PatchResult OBJECT CONTAINING THE PATCH AND METADATA OF PYTEST SUITES.
    """

    @abstractmethod
    async def synthesize_patch(self,attack_event:AttackEvents) -> PatchResult:
        """Synthesize a patch for the given attack event."""
        pass

class RegressionSandboxPort(ABC):
    """
    1. Base interface for the regression sandbox.
    2. IT TAKES PatchResult OBJECT FROM THE REMEDIATION ENGINE AND RUNS
    3. IT RETURNS A PatchResult OBJECT WITH UPDATED METADATA OF PYTEST SUITES.
    4. IF THE PATCH FAILS THE SANDBOX TESTS, IT WILL BE REJECTED AND NOT MERGED.
    5. IF THE PATCH PASSES THE SANDBOX TESTS, IT WILL BE SENT TO THE REPOSITORY MANAGER FOR MERGING.
    6. THE PATCH WILL BE MERGED ONLY IF IT PASSES ALL SANDBOX TESTS AND THE REPOSITORY MANAGER APPROVES IT.
    """
    @abstractmethod
    async def run_verification(self,patch_result:PatchResult):
        """Run verification tests on the given patch result."""
        pass

class RepositoryManagerPort(ABC):
    """
    1.IT TAKES VERIFIED PatchResult OBJECT FROM THE REGRESSION SANDBOX
    2. IT CREATES A PULL REQUEST FOR THE PATCH AND RETURNS THE PR URL.
    """
    @abstractmethod
    async def create_patch_pull_request(self,patch_result:PatchResult)-> str:
        """Create a pull request for the given patch result and return the PR URL."""
        pass
