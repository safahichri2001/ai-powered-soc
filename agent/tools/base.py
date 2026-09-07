from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class Tool:
    """A callable tool exposed to the agent.

    `handler` performs the actual side effect. It must only ever be
    invoked through `ToolExecutor.run()`, never directly.
    """

    name: str
    description: str
    handler: Callable[..., dict[str, Any]]
