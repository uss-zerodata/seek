"""One tag as the editor holds it: its name, description, issues and rules.

Pure. The editor in either front end changes a `TagEdit`; the session turns the
difference to the files as read into one `TagChange` (`Session.plan_tag_edit`).
A rule is kept with the loaded rule it came from, so a change replaces exactly
that rule in its own file, and a rule that changed on disk meanwhile is refused.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from seek.nmap import tagrules as tr


@dataclass(frozen=True, slots=True)
class RuleItem:
    raw: dict                          # seek's own form: name, grant, when
    origin: tr.Rule | None = None      # the rule as loaded; None for a new one
    deleted: bool = False

    @property
    def name(self) -> str:
        return str(self.raw.get("name", ""))

    @property
    def is_new(self) -> bool:
        return self.origin is None

    @property
    def changed(self) -> bool:
        return self.origin is not None and not self.deleted and self.raw != dict(self.origin.raw)

    @property
    def where(self) -> str:
        return str(self.origin.source) if self.origin is not None else "new"


@dataclass(frozen=True, slots=True)
class TagEdit:
    original: str | None               # the tag's name as loaded; None for a new tag
    name: str
    description: str = ""
    issues: tuple[tr.Issue, ...] = ()
    rules: tuple[RuleItem, ...] = ()
    manual_hosts: int = 0
    manual_services: int = 0
    # As loaded, to tell what changed.
    loaded_description: str = ""
    loaded_issues: tuple[tr.Issue, ...] = ()

    @property
    def renamed(self) -> bool:
        return self.original is not None and self.name != self.original

    @property
    def definition_changed(self) -> bool:
        return (self.description != self.loaded_description
                or self.issues != self.loaded_issues or self.original is None)

    @property
    def changed(self) -> bool:
        return (self.renamed or self.definition_changed
                or any(r.is_new or r.changed or r.deleted for r in self.rules))

    def with_rule(self, item: RuleItem, at: int | None = None) -> TagEdit:
        """`item` replacing the rule at `at`, or added first."""
        rules = list(self.rules)
        if at is None:
            rules.insert(0, item)
        else:
            rules[at] = item
        return replace(self, rules=tuple(rules))

    def toggle_delete(self, at: int) -> TagEdit:
        """A new rule is dropped; a loaded one is marked for deletion, or kept again."""
        rules = list(self.rules)
        item = rules[at]
        if item.is_new:
            del rules[at]
        else:
            rules[at] = replace(item, deleted=not item.deleted)
        return replace(self, rules=tuple(rules))


def from_loaded(name: str | None, loaded, entries=()) -> TagEdit:
    """The tag as the files say it; a new, empty one when `name` is None or unknown."""
    d = loaded.tags.get(name) if name else None
    hosts = sum(1 for e in entries if e.tag == name and e.port is None)
    services = sum(1 for e in entries if e.tag == name and e.port is not None)
    if d is None:
        return TagEdit(name if name and (hosts or services) else None, name or "",
                       manual_hosts=hosts, manual_services=services)
    return TagEdit(name, name, d.description, tuple(d.issues),
                   tuple(RuleItem(dict(r.raw), r) for r in d.rules), hosts, services,
                   d.description, tuple(d.issues))
