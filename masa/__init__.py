"""Multi-Agent Scaffolding Architecture (MASA / MASO) - Package Root."""

__version__ = "2.1.0"
__author__ = "masa Core Team"

from .framework import (
    AuditorAssertionEngine,
    ConfigCrypto,
    ContentSanitizer,
    MultiAgentFramework,
    SensitiveDataFilter,
    SubscriptionManager,
    TaskBroker,
    main,
)

__all__ = [
    "main",
    "MultiAgentFramework",
    "SubscriptionManager",
    "SensitiveDataFilter",
    "ConfigCrypto",
    "TaskBroker",
    "ContentSanitizer",
    "AuditorAssertionEngine",
]
