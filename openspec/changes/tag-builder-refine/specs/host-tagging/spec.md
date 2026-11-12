# Spec Delta

## MODIFIED Requirements

### Requirement: A port condition is satisfied by one port
A condition about a port SHALL be satisfied only when one single port of the host
meets every field of the condition. Without a `state` field, a port condition
SHALL require the port to be open.

#### Scenario: Fields describe one port
- **WHEN** a condition requires service `http` and product `nginx`, and the host has http on port 80 served by Apache and nginx on port 8443 with service `ssl`
- **THEN** the condition does not hold

#### Scenario: Open by default
- **WHEN** a condition names port 22 and no state, and the host has 22/tcp closed
- **THEN** the condition does not hold

#### Scenario: An explicit state
- **WHEN** a condition names port 22 with state `closed`, and the host has 22/tcp recorded closed
- **THEN** the condition holds

#### Scenario: One port of a list
- **WHEN** a condition names ports `80,8000-8999/tcp` and product `Zebra`, and the host has `Zebra httpd` on 8080/tcp
- **THEN** the condition holds

#### Scenario: Fields on one port of a list
- **WHEN** a condition names ports `80,8080` with service `http` and product `Zebra`, and the host has http by Apache on 80 and `Zebra httpd` on 8080 with service `ssl`
- **THEN** the condition does not hold

### Requirement: Text values are regular expressions by default
A text value SHALL be a regular expression that matches anywhere in the field and
ignores case. A condition SHALL be able to ask for case-sensitive matching, for a
literal value that matches as typed anywhere in the field, or for a value that
equals the whole field. Anchors SHALL be written in the expression. An expression
that does not compile SHALL disable its rule only.

#### Scenario: Matches anywhere, ignoring case
- **WHEN** a condition requires product `openresty`
- **THEN** it holds for the product `OpenResty web app server`

#### Scenario: Case-sensitive
- **WHEN** a condition requires title `READY` case-sensitively
- **THEN** it holds for `D2J201900995 - READY` and not for `ready`

#### Scenario: A literal value
- **WHEN** a condition requires the literal product `Jetty(i-jetty g2p5_0.08)`
- **THEN** it holds for exactly that text, and its parentheses and dots are not special

#### Scenario: An equal value
- **WHEN** a condition requires product `{equals: Zebra httpd}`
- **THEN** it holds for `zebra HTTPD` and not for `Zebra httpd 2.0`

#### Scenario: An equal value, case-sensitive
- **WHEN** a condition requires product `{equals: Zebra httpd, case: true}`
- **THEN** it holds for `Zebra httpd` and not for `zebra httpd`

#### Scenario: More than one kind of value
- **WHEN** a condition gives both `equals:` and `regex:` for one field
- **THEN** its rule is disabled with a problem that says to give exactly one of `regex:`, `literal:` or `equals:`

#### Scenario: A broken expression
- **WHEN** a rule contains the expression `Jetty(i-jetty`
- **THEN** that rule is disabled with a problem naming the file, the line and the error, and the tag's other rules still apply

### Requirement: The rule builder proposes shared facts
From the hosts it starts with, the builder SHALL propose the facts that at least
half of them share, each with how many selected hosts have it and how many hosts
outside the selection have it. Facts every selected host has SHALL come first,
the rarest first. Proposed text facts SHALL match their value with `equals`.

#### Scenario: Five printers
- **WHEN** the user starts the builder with five hosts with 80/tcp, 515/tcp and 9100/tcp open and the same title on port 80
- **THEN** the builder lists those ports and that title, each with "5/5 selected" and the number of other hosts that share it

#### Scenario: A fact few others have ranks first
- **WHEN** one shared fact is common in the scans and another is rare
- **THEN** the rare fact is listed first

#### Scenario: Values are literal
- **WHEN** a shared product is `Jetty(i-jetty g2p5_0.08)`
- **THEN** the proposed condition is `equals` that value: its parentheses and dots are not special, and a longer value that contains it does not match

#### Scenario: A host marked by mistake
- **WHEN** five printers and one web server are selected, and only the printers have 9100/tcp open
- **THEN** 9100/tcp open is proposed with "5/6 selected", and the web server is shown as not matched when it is required

### Requirement: The rule builder proposes exclusions
While the draft rule matches unselected hosts, the builder SHALL propose facts
that no selected host has, ranked by how many of those matches each one would
exclude. When no single fact excludes all of them, it SHALL also propose the best
combination of up to three. The proposals SHALL follow every change of the draft.

#### Scenario: One fact separates them
- **WHEN** the required facts match the five selected hosts and 500 others, and all 500 have 22/tcp open
- **THEN** the builder proposes excluding 22/tcp open, and shows that it excludes 500 of 500

#### Scenario: No fact separates them
- **WHEN** no single fact excludes all unselected matches
- **THEN** the builder proposes the best combination and says how many unselected hosts still match

#### Scenario: An exclusion that rests on an assumption
- **WHEN** a proposed exclusion is 22/tcp open and one selected host never had port 22 scanned
- **THEN** the builder says that the rule will match that host only as an assumption

#### Scenario: Nothing to exclude
- **WHEN** the draft matches only selected hosts
- **THEN** no exclusion is proposed

### Requirement: The rule builder previews before saving
The builder SHALL show at all times how many hosts the draft rule matches, how
many of the selected hosts it matches, and how many match only on an assumption.
The counts SHALL be the counts the saved rule gives.

#### Scenario: A preview
- **WHEN** the user requires three facts and excludes one
- **THEN** the builder shows the match counts and lists the hosts that would be tagged, updated after each change without another step

#### Scenario: A rule that matches nothing selected
- **WHEN** the draft excludes every selected host and the user saves
- **THEN** the builder says so, and saving needs a confirmation

## ADDED Requirements

### Requirement: A port condition accepts a list of ports
The `port:` of a condition SHALL accept one port, a list of ports, or text with
ports and ranges separated by commas, with an optional protocol after a slash.
A malformed list or a range outside 1-65535 SHALL disable the rule with a
problem that names the value.

#### Scenario: Text with ranges
- **WHEN** a condition has `port: "80,443,8000-8999/tcp"`
- **THEN** it tests 80, 443 and 8000 to 8999 on tcp

#### Scenario: A YAML list
- **WHEN** a condition has `port: [80, 8080]`
- **THEN** it tests 80 and 8080 on every protocol

#### Scenario: A reversed range
- **WHEN** a condition has `port: "9000-8000"`
- **THEN** its rule is disabled with a problem that names `9000-8000`, and the other rules load

### Requirement: A negated port list rests on the scanned ports
A negated condition with a list of ports SHALL hold for certain only when every
port of the list was scanned on the host. When some port of the list was not
scanned, it SHALL hold only as an assumption that names those ports.

#### Scenario: One port not scanned
- **WHEN** a rule has `not: {port: "22,23"}` and a host had 22 scanned closed and 23 not scanned
- **THEN** the host is tagged with an uncertainty label that names 23

### Requirement: The rule builder is one screen
The builder SHALL show the proposed facts, the exclusion proposals, the selection
and the matches on one screen. The user SHALL set each fact to ignored, required
or excluded in any order. Leaving the builder with unsaved changes SHALL ask for
a confirmation.

#### Scenario: Changing one's mind
- **WHEN** the user requires a fact, excludes another, then sets the first back to ignored
- **THEN** the counts follow each change, and no earlier choice is lost

#### Scenario: Leaving with changes
- **WHEN** the user presses Esc after changing the draft
- **THEN** the builder asks before it discards the draft

### Requirement: The rule builder shows the selection and the matches
The builder SHALL list the selected hosts, each marked as matched or not by the
draft, and the unselected hosts the draft matches, with their open ports and
title. The user SHALL be able to add a match to the selection, drop a host from
the selection, and exclude one matched host by its address. The proposals and
counts SHALL follow.

#### Scenario: A forgotten printer
- **WHEN** the draft matches two unselected hosts and the user adds one to the selection
- **THEN** the selection has six hosts, the proposals are recomputed for six, and one other match remains

#### Scenario: Excluding one host
- **WHEN** the user excludes the remaining unselected match by its address
- **THEN** the draft gets a condition that excludes that address, and it matches only the selection

### Requirement: The rule builder proposes a value shared on different ports
When the selected hosts have the same text value on some port, but not on the
same port, the builder SHALL propose that value with the list of those ports.

#### Scenario: Printers on two ports
- **WHEN** three selected hosts have product `Zebra httpd` on 80/tcp and two on 8080/tcp
- **THEN** the builder proposes product equals `Zebra httpd` on ports 80 and 8080/tcp, with "5/5 selected"

### Requirement: The rule builder proposes a shared word
When the selected hosts have differing values in one field, the builder SHALL
propose up to three words of at least four characters that every value contains,
longest first, as "contains" facts, next to the common beginning and end.

#### Scenario: Two models
- **WHEN** the selected hosts have the products `Zebra ZT410` and `ZTC Zebra ZD420`
- **THEN** the builder proposes product contains `Zebra`

### Requirement: The rule builder lets the user edit a fact
The user SHALL be able to edit any proposed fact. For a text fact the value, the
mode (equals, contains, starts with, ends with or regex) and case SHALL be
editable. For every fact with a port, the port scope (this port, a list of
ports, or any port) SHALL be editable. An invalid regex or port list SHALL be
reported, and the fact SHALL keep its earlier form.

#### Scenario: Widening a product
- **WHEN** the user edits "product equals `Zebra httpd` on 80/tcp" to contains `zebra`, any port
- **THEN** the condition saved is a case-ignoring search for `zebra` in the product of any open port

#### Scenario: Toggling equals
- **WHEN** the user switches a product fact from equals to contains, and back
- **THEN** the counts follow each switch, and the saved condition uses the last mode

#### Scenario: An open port on a list
- **WHEN** the user edits "80/tcp open" to the ports `80,8080`
- **THEN** the condition holds for hosts with 80 or 8080 open

#### Scenario: An invalid expression
- **WHEN** the user types the regex `Zebra(` in the editor
- **THEN** the editor says the expression is invalid, and the fact keeps its earlier form

### Requirement: Counts in the builder never block the viewer
Counts for an edited fact and for the draft SHALL be computed without blocking
the viewer, and SHALL show the last input. While a fact is edited, the editor
SHALL show how many selected and other hosts it matches, and SHALL warn when it
drops selected hosts.

#### Scenario: An edit that drops a host
- **WHEN** the user narrows a product fact so that one of five selected hosts no longer matches
- **THEN** the editor shows "4/5 selected" and a warning that one selected host is dropped

#### Scenario: Typing quickly
- **WHEN** the user types in the editor over 24 200 hosts
- **THEN** the viewer stays responsive, and the counts show the value last typed

### Requirement: The builder chooses same port or independent facts
The builder SHALL offer a toggle that is on by default. When it is on, required
facts with the same port scope SHALL form one condition that must hold on one
port. When it is off, each fact SHALL be its own condition. The counts SHALL
follow the toggle.

#### Scenario: Same port
- **WHEN** the user requires product contains `Zebra` and title ends with `READY`, both on any port, with the toggle on
- **THEN** the saved rule has one condition with both fields, and a host with the product on 80 and the title on 8080 is not counted

#### Scenario: Independent
- **WHEN** the same two facts are required with the toggle off
- **THEN** the saved rule has two conditions, and that host is counted

### Requirement: The builder saves into a chosen tag
Saving SHALL let the user pick an existing tag or enter a new valid name, name
the rule, and choose whether the rule tags the host, the matched services, or
both. The rule SHALL then go to the tag editor, and SHALL be written when the
editor is saved. A builder started from services SHALL offer the services grant.

#### Scenario: An existing tag
- **WHEN** the user saves the draft, picks the existing tag `zebra`, and saves the tag editor
- **THEN** the rule is added to `zebra` in the project's tag file, under the name the user gave

#### Scenario: Nothing written before the editor
- **WHEN** the user saves the draft and then leaves the tag editor without saving
- **THEN** no file is changed

#### Scenario: A service rule
- **WHEN** the user saves a rule with the services grant
- **THEN** only the ports that satisfied its port conditions carry the tag

### Requirement: The builder switches between ports and their hosts
A builder started from services SHALL propose facts of those ports only, and
SHALL let the user switch to the whole hosts the services belong to, and back.
The selection and the chosen facts SHALL be kept.

#### Scenario: From a port to its host
- **WHEN** the user starts the builder on 515/tcp of five printers and switches to the hosts
- **THEN** facts of every port of the five printers are proposed, and the chosen facts stay chosen

### Requirement: One editor holds everything about a tag
The tag editor SHALL show and change a tag's name, description, issues and rules,
and SHALL show how many hosts and services carry it by hand. It SHALL open after
the builder saves a rule, and for any tag from the tag menu. Nothing SHALL be
written until it is saved, and then everything SHALL be written as one change.

#### Scenario: A rule, a description and an issue at once
- **WHEN** the user builds a rule, saves it to the new tag `zebra`, types a description and adds an issue in the editor, and saves
- **THEN** the project's tag file holds the rule, the description and the issue

#### Scenario: Leaving with changes
- **WHEN** the user presses Esc after changing the tag
- **THEN** the editor asks before it discards the changes

### Requirement: Issues carry descriptions and references
An issue SHALL have a title, a severity, an optional description and optional
references. The editor SHALL edit all of them, and a record SHALL show the tag's
description and each issue's description and references under the tag.

#### Scenario: An issue in a record
- **WHEN** a host carries `zebra`, whose issue `Admin PIN` has the description `4 digits` and the reference `https://example.test/a`
- **THEN** the host's record shows the issue with its description and reference

### Requirement: The editor edits and deletes rules in their files
A rule opened from the editor SHALL be edited in the builder and come back to the
editor. Saving SHALL replace each changed rule and remove each deleted rule in
the file it was read from, and refuse when that rule changed on disk.

#### Scenario: Deleting a rule
- **WHEN** the user deletes the rule `one` of `web` in the editor and saves
- **THEN** `one` is gone from its file, and the other rules of the file are unchanged

#### Scenario: A rule in the colleague's format
- **WHEN** the user changes or deletes a rule written in categorize_systems' format
- **THEN** saving is refused with the file and line, and nothing is written

### Requirement: A rename reaches every project file
Renaming a tag SHALL rename it in every project file that says it: its
definition, `tag:` and `has_tag:` conditions, manual tags, and the colleague's
`host_tags` and `service_tags`. A name another tag has SHALL be refused.

#### Scenario: Renaming a tag that others use
- **WHEN** the tag `web-only` is used by the rule of `inner` and by a manual tag, and the user renames it to `web`
- **THEN** `inner` asks for `web`, the manual tag is `web`, and `web-only` is gone

#### Scenario: Onto an existing name
- **WHEN** the user renames `a` to `b` and `b` exists
- **THEN** saving is refused, saying that `b` exists already

### Requirement: Rewriting a person's rule file is confirmed
A change that writes a `seek-rules.yaml` SHALL name the file and say that it is
written in seek's layout, without its comments, and SHALL be written only when
the user confirms.

#### Scenario: Editing a rule of a hand-written file
- **WHEN** the user changes a rule read from `seek-rules.yaml` and saves the editor
- **THEN** the editor names `seek-rules.yaml` and asks, and the file is unchanged until the user confirms

### Requirement: The builder starts from marks, a row, the view or a rule
The builder SHALL start from the marked rows, or else from the row under the
cursor. When nothing is marked and the view is filtered, it SHALL offer the rows
in the view. It SHALL also open an existing rule from the tag editor, and hand
the changed rule back to it. A rule the builder cannot represent SHALL say why
and SHALL not open.

#### Scenario: From the filtered view
- **WHEN** nothing is marked, the view is filtered to 23 hosts, and the user presses `T` and picks the rows in view
- **THEN** the builder starts with those 23 hosts

#### Scenario: Editing a saved rule
- **WHEN** the user opens the rule `built from 5 host(s)` of tag `zebra` from the tag editor, widens one fact, and saves the editor
- **THEN** that rule is replaced in its file, and the other rules of the file are unchanged

#### Scenario: The rule changed on disk
- **WHEN** the rule was changed in its file after the builder opened it, and the user saves
- **THEN** nothing is written, and the builder says that the rule changed and must be reloaded

#### Scenario: A rule beyond the builder
- **WHEN** the user opens a rule that uses `any:` or a rule in the colleague's format
- **THEN** the builder says it cannot edit that rule and names the file and the line
