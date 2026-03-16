"""Domain and path pattern matching for config rules.

* matches exactly one label or path segment. | separates alternative patterns.
"""

from __future__ import annotations

import fnmatch


__all__ = ["Pattern"]


class Pattern:
    """Static helpers for pattern matching."""

    @staticmethod
    def normalise(domain: str, path: str = "/") -> str:
        """Canonicalise a domain and path into a single string.

        Result is domain or domain/path (lowercased, no leading/trailing path
        slashes). Does not validate; empty domain is allowed.
        """
        d = domain.rstrip(".").lower()
        p = (path or "/").strip("/").lower()
        return f"{d}/{p}" if p else d

    @staticmethod
    def matches(pattern: str, target: str) -> bool:
        """True if target matches pattern (or any |-separated alternative). * = one label/segment."""
        t = target.strip().lower()
        for alt in (_s for s in pattern.split("|") if (_s := s.strip())):
            if Pattern._match_one(alt, t):
                return True
        return False

    @staticmethod
    def _get_match_one_internals(p_or_t: str) -> tuple[list[str], list[str]]:
        """Return (path_segments, domain_label_list) for the pattern or target string."""
        if "/" in p_or_t:
            domain, path = p_or_t.split("/", 1)
            path_segments = path.split("/") if path else []
        else:
            domain, path_segments = p_or_t, []
        # (path_segments, domain_labels)
        return path_segments, domain.split(".")

    @staticmethod
    def _match_one(pattern: str, target: str) -> bool:
        """True if target matches pattern. * = one label/segment."""
        pattern_path_segments, pattern_domain_parts = Pattern._get_match_one_internals(
            pattern
        )
        target_path_segments, target_domain_paths = Pattern._get_match_one_internals(
            target
        )

        # If not same number of labels, no match
        if len(pattern_domain_parts) != len(target_domain_paths):
            return False

        # If not all labels match, no match
        if not all(
            Pattern._glob_segment(p, t)
            for p, t in zip(pattern_domain_parts, target_domain_paths, strict=True)
        ):
            return False

        # If no pattern path segments, same domain therefore match
        if not pattern_path_segments:
            return True

        # If not same number of path segments, no match
        if len(pattern_path_segments) != len(target_path_segments):
            return False

        # Finally, return whether all path segments match
        return all(
            Pattern._glob_segment(p, t)
            for p, t in zip(pattern_path_segments, target_path_segments, strict=True)
        )

    @staticmethod
    def _glob_segment(pattern_segment: str, target_segment: str) -> bool:
        """True if target segment matches pattern segment. * = one label/segment."""
        if pattern_segment == "*":
            return bool(target_segment)
        if "*" not in pattern_segment:
            return pattern_segment == target_segment
        return bool(fnmatch.fnmatch(target_segment, pattern_segment))
