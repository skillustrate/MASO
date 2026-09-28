#!/usr/bin/env python3
"""Convenience top-level launcher for MASA / MASO."""

import sys
from masa.framework import (
    main,
    MultiAgentFramework,
    SubscriptionManager,
    SensitiveDataFilter,
    ConfigCrypto,
    TaskBroker,
    ContentSanitizer,
    AuditorAssertionEngine,
    USER_CONFIG_PATH,
    MASA_HOME_DIR,
)

if __name__ == "__main__":
    main()
