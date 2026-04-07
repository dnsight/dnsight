"""Base class for MergeableConfig."""

from __future__ import annotations

from typing import Any, Self

from pydantic import BaseModel, ConfigDict


__all__ = ["MergeableConfig"]


class MergeableConfig(BaseModel):
    """
    Base for all config blocks. Provides recursive partial merge
    and a generic resolve() for layering configs together.
    """

    model_config = ConfigDict(frozen=True)

    def merge(self, partial: Self) -> Self:
        """Return a new instance with partials explicitly-set fields merged into self.

        Recurses into nested MergeableConfig children.

        Args:
            partial: The partial config to merge into self.

        Returns:
            A new instance with the merged config.
        """

        updates: dict[str, Any] = {}

        for field_name in partial.model_fields_set:
            incoming = getattr(partial, field_name)
            current = getattr(self, field_name)

            if isinstance(current, MergeableConfig) and isinstance(
                incoming, MergeableConfig
            ):
                updates[field_name] = current.merge(incoming)
            else:
                updates[field_name] = incoming

        return self.model_copy(update=updates)

    @classmethod
    def resolve(
        cls, config: Self | None = None, partial: Self | None = None, **kwargs: Any
    ) -> Self:
        """Generic resolver: layer config -> partial -> kwargs into a single
        resolved instance. Each layer only applies explicitly-set fields.

        Args:
            config: The base config to start with. Defaults to None.
            partial: A partial config to merge on top of the base. Defaults to None.
            **kwargs: Field overrides to merge into the config.

        Returns:
            A new instance with the resolved config.
        """
        base: Self = config if config is not None else cls()

        if partial is not None:
            base = base.merge(partial)

        if kwargs:
            base = base.merge(cls(**kwargs))

        return base
