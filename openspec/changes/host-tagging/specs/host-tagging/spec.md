## Purpose

Lets a tester name kinds of hosts and services, and attach known issues to
them, either by rules evaluated over the scan and capture data or by hand, so
that similar systems and their known weaknesses are found at a glance.

## ADDED Requirements

### Requirement: A tag is a named definition
A tag SHALL have a name and MAY have a description, known issues and rules. A
name SHALL be 1 to 64 characters from lowercase letters, digits, `.`, `_` and
`-`, starting with a letter or digit. Names SHALL be compared case-insensitively
and shown in lowercase. A tag that is used but never defined SHALL behave as a
tag with no description and no issues.

#### Scenario: A defined tag
- **WHEN** a rule file defines tag `zebra-zd420` with a description and one issue
- **THEN** the tag is listed with that description and issue

#### Scenario: A used but undefined tag
- **WHEN** a rule grants `printer` and no file defines `printer`
- **THEN** hosts are tagged `printer`, and the tag has no description and no issues

#### Scenario: Names are case-insensitive
- **WHEN** one rule grants `Printer` and another grants `printer`
- **THEN** both grant the same tag, shown as `printer`

#### Scenario: An invalid name
- **WHEN** a rule file defines a tag named `my printer`
- **THEN** that tag is disabled with a problem naming the file, the line and the reason, and every other tag still loads

### Requirement: A tag carries known issues
An issue SHALL have a title and a severity of `info`, `low`, `medium`, `high`
or `critical`, and MAY have a description and references. Every host or service
that carries the tag SHALL show the tag's issues, whichever rule or manual entry
granted the tag.

#### Scenario: An issue reaches every tagged host
- **WHEN** tag `zebra-zd420` has the issue "Admin interface protected by a 4-digit PIN" with severity `medium`, and two rules grant the tag
- **THEN** every host granted the tag by either rule shows that issue and its severity

#### Scenario: An unknown severity
- **WHEN** an issue has severity `severe`
- **THEN** the issue is rejected with a problem that lists the allowed severities, and the tag still loads without it

### Requirement: A tag is granted when any of its rules matches
A tag SHALL be granted to a host when at least one of its rules matches the host.
A rule SHALL match when all of its conditions hold. A rule with no conditions
SHALL be rejected.

#### Scenario: Two rules for one tag
- **WHEN** tag `printer` has a rule for ports 515 and 9100 and a rule for the title "Web Image Monitor"
- **THEN** a host matching either rule is tagged `printer`

#### Scenario: All conditions must hold
- **WHEN** a rule requires 80/tcp open and 830/tcp open
- **THEN** a host with only 80/tcp open is not matched

#### Scenario: An empty rule
- **WHEN** a rule has no conditions
- **THEN** the rule is rejected with a problem, because it would match every host

### Requirement: A port condition is satisfied by one port
A condition about a port SHALL be satisfied only when one single port of the host
meets every field of the condition. Without a `state` field, a port condition
SHALL require the port to be open.

#### Scenario: Fields describe one port
- **WHEN** a condition requires service `http` and product `nginx`, and the host has http on port 80 served by Apache and nginx on port 8443 with service `https-alt`
- **THEN** the condition does not hold

#### Scenario: Open by default
- **WHEN** a condition names port 22 and no state, and the host has 22/tcp closed
- **THEN** the condition does not hold

#### Scenario: An explicit state
- **WHEN** a condition names port 22 with state `closed`, and the host has 22/tcp recorded closed
- **THEN** the condition holds

### Requirement: Conditions cover the scan and the captures
A port condition SHALL be able to test the port number, protocol, state, service
name, product, version, extra information, CPE, tunnel, any script's id and
output, and the certificate subject and issuer. With a capture, it SHALL also
test the page title, body, final URL, headers, technologies and network log.

#### Scenario: A certificate issuer
- **WHEN** a condition requires the certificate issuer to match `RICOH COMPANY`, and port 7443's `ssl-cert` output names that organisation as issuer
- **THEN** the condition holds for port 7443

#### Scenario: A page title from a capture
- **WHEN** a condition requires port 80's title to match `Web Image Monitor`, and the capture of port 80 has that title
- **THEN** the condition holds

#### Scenario: Script output
- **WHEN** a condition requires script `http-server-header` with output matching `openresty`
- **THEN** it holds for a port whose script output says `openresty`

### Requirement: Conditions cover the host
A host condition SHALL be able to test the address, by network or by expression,
every name the host is known by, the best OS match, host script output, and
whether the host carries another tag.

#### Scenario: A network
- **WHEN** a condition requires the address to be in `10.20.0.0/16`
- **THEN** only hosts in that network satisfy it

#### Scenario: A name from a certificate
- **WHEN** a condition requires a hostname matching `\.sdlan\.example\.net$`, and the host is known by that name only through its certificate
- **THEN** the condition holds

#### Scenario: Another tag
- **WHEN** tag `ricoh` has a rule requiring tag `printer` and the title "Web Image Monitor"
- **THEN** a host is tagged `ricoh` only if it is also tagged `printer` and has that title

### Requirement: A condition can be negated
A negated port condition SHALL hold when no port of the host satisfies the
condition. A negated host condition SHALL hold when the host condition does not.

#### Scenario: Exclude hosts with ssh
- **WHEN** a rule requires 80/tcp open with title "Printer Home Page" and has a negated condition for 22/tcp open, and a host has 80/tcp with that title and 22/tcp open
- **THEN** the host is not matched

#### Scenario: Negation is not per port
- **WHEN** a negated condition excludes service `ssh`, and the host has ssh on 22 and http on 80
- **THEN** the negated condition does not hold, although port 80 is not ssh

#### Scenario: A negated tag
- **WHEN** a rule requires tag `printer` and excludes tag `ricoh`
- **THEN** printers not tagged `ricoh` are matched

### Requirement: Text values are regular expressions by default
A text value SHALL be a regular expression that matches anywhere in the field and
ignores case. A condition SHALL be able to ask for case-sensitive matching, or
for a literal value that matches as typed. Anchors SHALL be written in the
expression. An expression that does not compile SHALL disable its rule only.

#### Scenario: Matches anywhere, ignoring case
- **WHEN** a condition requires product `openresty`
- **THEN** it holds for the product `OpenResty web app server`

#### Scenario: Case-sensitive
- **WHEN** a condition requires title `READY` case-sensitively
- **THEN** it holds for `D2J201900995 - READY` and not for `ready`

#### Scenario: A literal value
- **WHEN** a condition requires the literal product `Jetty(i-jetty g2p5_0.08)`
- **THEN** it holds for exactly that text, and its parentheses and dots are not special

#### Scenario: A broken expression
- **WHEN** a rule contains the expression `Jetty(i-jetty`
- **THEN** that rule is disabled with a problem naming the file, the line and the error, and the tag's other rules still apply

### Requirement: A negation without evidence is an assumption
When a negated condition holds only because the data it reads is missing, the
tag SHALL still be granted and SHALL be marked uncertain. The mark SHALL name
the missing evidence. Data is missing when no scan of the host probed the port,
the host timed out, or no capture exists for a capture field.

#### Scenario: A port nobody scanned
- **WHEN** a rule excludes 22/tcp open, and the only scan of a host probed ports 80, 515 and 9100
- **THEN** the host is tagged, marked uncertain, and the mark says that 22/tcp was not scanned

#### Scenario: A port scanned and not open
- **WHEN** a rule excludes 22/tcp open, and a scan of the host probed port 22 and did not find it open
- **THEN** the host is tagged and not marked uncertain

#### Scenario: A host that timed out
- **WHEN** a rule excludes 22/tcp open, and the host timed out in the scan that listed port 22
- **THEN** the host is tagged and marked uncertain

#### Scenario: A certain match is preferred
- **WHEN** a tag has two rules, one matching with an assumption and one matching without
- **THEN** the tag is granted without the uncertain mark

#### Scenario: An uncertain tag used by another tag
- **WHEN** tag `zebra` is uncertain on a host, and tag `zebra-zd420` requires tag `zebra`
- **THEN** `zebra-zd420` is uncertain on that host too, with the same missing evidence

### Requirement: A positive condition without data does not match
A positive condition whose data is missing SHALL NOT hold. When a capture holds
no page body, a body condition SHALL be reported as not evaluated for that
service, never as a plain non-match.

#### Scenario: No capture
- **WHEN** a rule requires a title on port 80 and port 80 has no capture
- **THEN** the rule does not match that host

#### Scenario: A capture without bodies
- **WHEN** a rule requires the body to match `Zebra Technologies`, and the capture was made without bodies
- **THEN** the rule does not match, and the tag's problems say how many services could not be evaluated and why

### Requirement: Service tags go to the ports that matched
A rule SHALL be able to grant a tag to the host, to its services, or both. A
service tag SHALL go to every port that satisfied a positive port condition of
the matching rule. A negated condition SHALL never select a service.

#### Scenario: Service tag on the matched port
- **WHEN** a rule requires 80/tcp with title "Web Image Monitor" and 515/tcp open, and grants service tag `ricoh-web-ui`
- **THEN** ports 80 and 515 carry the tag, and no other port does

#### Scenario: A negation selects nothing
- **WHEN** a rule excludes 22/tcp open and grants a service tag
- **THEN** port 22 never carries that tag

### Requirement: Tags that depend on each other are ordered
Tag conditions SHALL be evaluated in dependency order, whatever the order of the
files and rules. Tags that depend on each other in a cycle SHALL be disabled with
a problem that names every tag in the cycle. Tags outside the cycle SHALL still
apply.

#### Scenario: Order does not matter
- **WHEN** the rule for `ricoh` requires tag `printer` and appears before the rule for `printer`
- **THEN** `ricoh` is granted exactly as if the order were reversed

#### Scenario: A cycle
- **WHEN** tag `a` requires tag `b` and tag `b` excludes tag `a`
- **THEN** both are disabled, a problem names `a` and `b`, and other tags apply

### Requirement: The colleague's rule format is read unchanged
Seek SHALL read a `categorize_systems` rules file without changes and grant the
same host tags. Text SHALL match as an expression that ignores case, which can
widen a match. Service tags SHALL follow seek's own rule, not the intersection
of patterns that `categorize_systems` uses.

#### Scenario: The colleague's example file
- **WHEN** the example rules of `categorize_systems` are applied to a scan with a Ricoh printer, a Catalyst switch and an AXIS camera
- **THEN** the hosts carry the same host tags as in `categorize_systems`

#### Scenario: Every pattern type is accepted
- **WHEN** a file uses `nmap_port`, `html_title`, `html_body`, `html_redirect`, `has_tag`, `service_match`, `all` and `any`
- **THEN** every rule loads, and `service_match` keys written with a colon such as `cert:issuer` are understood

#### Scenario: Service tags from an `all` pattern
- **WHEN** a colleague's rule combines `html_title` on port 80 and `nmap_port` 515 under `all`, and grants a service tag
- **THEN** ports 80 and 515 carry the service tag, where `categorize_systems` would tag no port

#### Scenario: A gowitness pattern without a port
- **WHEN** an `html_title` pattern has no port
- **THEN** it holds when the capture of any port of the host has a matching title

### Requirement: Seek's own rule format extends the colleague's
A rule file SHALL be able to define tags with descriptions, issues, rules, and a
scope of host, service or both. Rules SHALL accept `not`, more fields, and
literal or case-sensitive values. Unknown keys SHALL disable the rule that holds
them, with a problem naming the key.

#### Scenario: Both formats in one file
- **WHEN** a file has a `rules:` list in the colleague's format and a `tags:` section that defines issues for a tag the list grants
- **THEN** hosts granted the tag by the list show the issues from `tags:`

#### Scenario: A misspelt key
- **WHEN** a condition has the key `prodcut`
- **THEN** its rule is disabled with a problem that names `prodcut`, and the other rules load

### Requirement: Rule files are found below every opened folder
Seek SHALL read `seek-rules.yaml` and `seek-tags.yaml` in every folder below the
opened folders, by the rules that find scans, and the global `rules.yaml` and
`tags.yaml` in the config directory. Every file found SHALL apply to every scan
that is open.

#### Scenario: Nested project folders
- **WHEN** the user opens `engagement/`, which holds `alice/seek-rules.yaml`, `bob/seek-rules.yaml` and scans in both folders
- **THEN** the rules from both files are applied to the scans of both folders

#### Scenario: A file named on the command line
- **WHEN** the user opens `alice/scan.xml` without its folder
- **THEN** the rule files in `alice/` itself are read, and its subfolders are not searched

#### Scenario: No rule files
- **WHEN** no rule file exists anywhere
- **THEN** the viewer works as before and shows no tags and no problem

### Requirement: A more specific definition wins, with a warning
When two files define the same tag differently, a file in a descendant folder
SHALL replace the definition of a file in an ancestor folder, and every project
file SHALL replace the global files. Definitions from unrelated files SHALL be
merged. Both cases SHALL show a warning naming the files. Identical definitions
SHALL not warn.

#### Scenario: A project overrides the global file
- **WHEN** the global file and the project define `zebra-zd420` with different issues
- **THEN** the project's definition applies, and a warning names both files

#### Scenario: A subfolder overrides its parent
- **WHEN** `engagement/seek-rules.yaml` and `engagement/alice/seek-rules.yaml` define `printer` differently
- **THEN** the definition from `alice/` applies, and a warning names both files

#### Scenario: Siblings are merged
- **WHEN** `alice/seek-rules.yaml` and `bob/seek-rules.yaml` define `printer` with different rules
- **THEN** a host matching any of the rules is tagged, issues are combined, and a warning names both files

#### Scenario: A copy is not a collision
- **WHEN** a tag was copied to the global file and is still defined the same way in the project
- **THEN** no warning is shown

### Requirement: A broken file never stops the viewer
A rule or tag file that cannot be read or parsed SHALL be skipped, and the
problem SHALL name the file and, where known, the line. Every other file SHALL
still apply. Problems SHALL be listed where tags are listed.

#### Scenario: Invalid YAML
- **WHEN** `bob/seek-rules.yaml` contains a YAML syntax error
- **THEN** the viewer opens, tags from every other file apply, and the problem names the file and the line

#### Scenario: Not a rule file
- **WHEN** a `seek-rules.yaml` holds a YAML list rather than a mapping
- **THEN** it is skipped with a problem that says what was expected

#### Scenario: An unreadable file
- **WHEN** a rule file exists but cannot be read for lack of permission
- **THEN** it is skipped with a problem, and the viewer opens

### Requirement: Rule files are reloaded when they change
Seek SHALL check its rule and tag files for changes whenever the scans are read
again, and on an explicit reload. A changed file SHALL be read again, and tags
SHALL be recomputed.

#### Scenario: Editing a rule while the viewer is open
- **WHEN** the user edits `seek-rules.yaml` in an editor and then asks for a reload
- **THEN** the tags reflect the edited rules, without restarting the viewer

### Requirement: Hosts and services can be tagged by hand
The user SHALL be able to add or remove a tag on the selected or marked rows. A
host SHALL be keyed by its IP address, and a service by address, protocol and
port. A host or service SHALL be able to carry several tags.

#### Scenario: Tagging marked hosts
- **WHEN** the user marks three hosts and tags them `explored`
- **THEN** the three hosts carry `explored` in every view

#### Scenario: Tagging a service
- **WHEN** the user tags 443/tcp of 10.0.0.5 as `high-value`
- **THEN** that service carries the tag, and 80/tcp of the same host does not

#### Scenario: Several tags
- **WHEN** a host is tagged `explored` and `high-value`
- **THEN** it carries both

#### Scenario: Removing a tag
- **WHEN** the user removes `explored` from a host that a rule also tags `explored`
- **THEN** the manual entry is removed, and the host still carries `explored` from the rule

#### Scenario: Addresses are compared in canonical form
- **WHEN** a manual entry names `2001:db8:0:0::1` and a scan names `2001:db8::1`
- **THEN** the entry applies to that host

### Requirement: Manual tags persist in the project
Manual tags SHALL be saved in `seek-tags.yaml` in the first opened folder, or in
the folder of the first opened file. A removal SHALL change every file that
holds the entry. Entries for hosts not in the current scans SHALL be kept.

#### Scenario: Persisting across sessions
- **WHEN** the user tags a host, quits, and opens the same folder again
- **THEN** the host still carries the tag

#### Scenario: A host not loaded
- **WHEN** the user opens only `alice/`, whose `seek-tags.yaml` has entries for hosts that only `bob/` scanned
- **THEN** those entries are kept unchanged, and the tag list says how many entries match no loaded host

#### Scenario: Removing an entry from a subfolder's file
- **WHEN** the user opens `engagement/` and removes a tag whose entry is stored in `alice/seek-tags.yaml`
- **THEN** the entry is removed from `alice/seek-tags.yaml`

### Requirement: Writing a tag file never loses data
Seek SHALL write a tag file as a whole, replacing it in one step. It SHALL apply
each change to the file as it is on disk at that moment. It SHALL never rewrite
a file it could not parse, and SHALL never write a `seek-rules.yaml` or
`rules.yaml`.

#### Scenario: Two writers
- **WHEN** the terminal viewer and a browser session on another machine both add tags to the same `seek-tags.yaml`
- **THEN** the file holds both additions

#### Scenario: A file seek could not parse
- **WHEN** `seek-tags.yaml` contains a syntax error and the user adds a tag
- **THEN** the file is left unchanged, the tag is not saved, and the user is told why

#### Scenario: A read-only folder
- **WHEN** the opened folder cannot be written to
- **THEN** manual tagging says that tags cannot be saved there, and nothing else changes

#### Scenario: Interrupted write
- **WHEN** seek is killed while writing `seek-tags.yaml`
- **THEN** the file holds either the old or the new content, never a mix

### Requirement: A manual tag can become a definition
The user SHALL be able to give a tag a description, issues and rules from the
viewer. These SHALL be saved in the project's `seek-tags.yaml`. The user SHALL be
able to copy a tag definition, without its manual entries, to the global
`tags.yaml`.

#### Scenario: Adding an issue to a manual tag
- **WHEN** the user adds the issue "Default credentials" with severity `high` to tag `camera-x`
- **THEN** every host carrying `camera-x` shows the issue, and the issue is saved in `seek-tags.yaml`

#### Scenario: Copying to the global file
- **WHEN** the user copies tag `zebra-zd420` to the global file
- **THEN** `tags.yaml` in the config directory holds its definition, and no host address

### Requirement: The rule builder proposes shared facts
From marked hosts or services, the builder SHALL list the facts that all of them
share. Each fact SHALL show how many hosts outside the selection share it. The
user SHALL choose which facts become conditions.

#### Scenario: Five printers
- **WHEN** the user marks five hosts with 80/tcp, 515/tcp and 9100/tcp open and the same title on port 80
- **THEN** the builder lists those ports and that title, each with the number of other hosts that share it

#### Scenario: A fact few others have ranks first
- **WHEN** one shared fact is common in the scans and another is rare
- **THEN** the rare fact is listed first

#### Scenario: Values are literal
- **WHEN** a shared product is `Jetty(i-jetty g2p5_0.08)`
- **THEN** the proposed condition is a literal value

### Requirement: The rule builder proposes exclusions
When the chosen facts also match unselected hosts, the builder SHALL propose
facts that no selected host has, ranked by how many unselected matches each one
excludes. When no single fact excludes all of them, it SHALL propose the best
combination of up to three.

#### Scenario: One fact separates them
- **WHEN** the chosen facts match the five selected hosts and 500 others, and all 500 have 22/tcp open
- **THEN** the builder proposes "22/tcp not open" and shows that it keeps 5 of 5 and excludes 500 of 500

#### Scenario: No fact separates them
- **WHEN** no single fact excludes all unselected matches
- **THEN** the builder proposes the best combination and says how many unselected hosts still match

#### Scenario: An exclusion that rests on an assumption
- **WHEN** a proposed exclusion is "22/tcp not open" and one selected host never had port 22 scanned
- **THEN** the builder says that the rule will match that host only as an assumption

### Requirement: The rule builder previews before saving
Before a rule is saved, the builder SHALL show how many hosts it matches, how
many of them were selected, and how many match only with an assumption.

#### Scenario: A preview
- **WHEN** the user chooses three facts and one exclusion
- **THEN** the builder shows the match counts and lists the hosts that would be tagged

#### Scenario: A rule that matches nothing selected
- **WHEN** the chosen facts exclude every selected host
- **THEN** the builder says so, and saving needs a confirmation

### Requirement: Tagging does not slow the viewer
Tags SHALL be computed off the event loop, in the work that builds the views.
The viewer SHALL stay responsive while they are computed, and SHALL show tags
once they are ready.

#### Scenario: A large engagement
- **WHEN** 24 200 hosts are open with 200 rules
- **THEN** the list can be scrolled and filtered while tags are computed, and tags appear when ready

#### Scenario: A slow body condition
- **WHEN** a body condition runs over a large capture database
- **THEN** the viewer stays responsive, and the body read is capped per page

### Requirement: Tagging sends nothing anywhere
Rule evaluation, manual tags and the builder SHALL work only on local data. They
SHALL NOT make a network request.

#### Scenario: Offline
- **WHEN** the machine has no network
- **THEN** every tagging feature works
