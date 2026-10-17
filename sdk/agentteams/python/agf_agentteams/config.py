"""Explicit collector settings; no credentials are written to the outbox."""
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID


@dataclass(frozen=True)
class Config:
    platform_url: str
    source_id: str
    binding_id: str
    collector_key: str = field(repr=False)
    spool_dir: Path
    max_items: int = 10_000
    max_bytes: int = 16 * 1024 * 1024
    max_disk_bytes: int = 64 * 1024 * 1024
    batch_items: int = 100
    batch_bytes: int = 256 * 1024
    request_timeout: float = 5.0
    expected_scope: str | None = None
    expected_mocked: bool | None = None

    def __post_init__(self):
        address = urlsplit(self.platform_url)
        if (address.scheme not in {"http", "https"} or not address.hostname
                or address.username is not None or address.password is not None
                or address.query or address.fragment):
            raise ValueError("platform_url must be an HTTP(S) URL without credentials, query or fragment")
        try:
            address.port
            source = str(UUID(self.source_id))
            binding = str(UUID(self.binding_id))
            scope = str(UUID(self.expected_scope)) if self.expected_scope else None
        except (ValueError, TypeError, AttributeError) as error:
            raise ValueError("source_id, binding_id and optional scope must be UUIDs") from error
        if not isinstance(self.collector_key, str) or not self.collector_key or any(
                character.isspace() or ord(character) < 32 for character in self.collector_key):
            raise ValueError("collector_key is missing or contains whitespace")
        limits = (self.max_items, self.max_bytes, self.max_disk_bytes, self.batch_items, self.batch_bytes)
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in limits):
            raise ValueError("queue and batch limits must be positive integers")
        if (self.max_items > 1_000_000 or not 256 * 1024 <= self.max_disk_bytes <= 256 * 1024 * 1024
                or self.max_disk_bytes < self.max_bytes + 64 * 1024
                or self.batch_items > 100 or self.batch_bytes > 256 * 1024
                or self.batch_bytes > self.max_bytes or not 0.1 <= self.request_timeout <= 30):
            raise ValueError("queue or transport limits are outside the supported bounds")
        if self.expected_mocked is not None and type(self.expected_mocked) is not bool:
            raise ValueError("expected_mocked must be a boolean or None")
        object.__setattr__(self, "platform_url", urlunsplit(
            (address.scheme, address.netloc, address.path.rstrip("/"), "", "")))
        object.__setattr__(self, "source_id", source)
        object.__setattr__(self, "binding_id", binding)
        object.__setattr__(self, "expected_scope", scope)
        object.__setattr__(self, "spool_dir", Path(self.spool_dir).absolute())

    @property
    def endpoint(self):
        return f"{self.platform_url}/api/v1/alicloud/agentteams/audit-sources/{self.source_id}/events"

    @property
    def identity(self):
        # The binding is immutable for a queue. Changing a Key does not change its identity.
        return {"schema": 1, "platform": self.platform_url, "source": self.source_id,
                "binding": self.binding_id, "scope": self.expected_scope,
                "mocked": self.expected_mocked}
