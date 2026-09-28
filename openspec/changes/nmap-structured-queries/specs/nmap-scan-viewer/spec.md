## ADDED Requirements

### Requirement: The filter accepts field terms and logical operators
Alongside fuzzy terms and address ranges, the filter SHALL accept field terms
that are tested against the scan model rather than the row's text:

- `open:PORT` and `open:PORT/PROTO` SHALL match a port the scan found open;
- `closed:PORT` and `closed:PORT/PROTO` SHALL match a port the scan recorded in
  any state other than open — closed, filtered or `open|filtered`;
- a port the scan never recorded SHALL match neither;
- `service:VALUE` SHALL match a port whose service name contains the value, and
  `product:VALUE` one whose detected product contains it, case-insensitively,
  with `^` and `$` anchoring as in the fuzzy grammar.

The port-state keys SHALL be `open:` and `closed:`, so that "up" keeps its one
meaning: the host rule.

Terms SHALL combine with `AND`, `OR` and `NOT` written in uppercase, with `|` for
OR, with `!` for NOT as today, and with parentheses; a space between terms SHALL
mean AND; NOT SHALL bind tighter than AND, and AND tighter than OR. Lowercase
`and`, `or` and `not` SHALL remain ordinary search words, and a `key:` that is
not one of the fields SHALL remain an ordinary search term.

Field terms joined by AND SHALL describe the same port: a row matches only if one
of its ports satisfies all of them. `NOT` applied to field terms SHALL mean that
none of the row's ports satisfies them. For a row that stands for several ports —
a host, a service across hosts, a grouping bucket — the row SHALL match when any
of its ports, or pairs, does.

A filter that uses none of this syntax SHALL behave exactly as before, including
the union of several address ranges, which SHALL also hold for ranges joined by
AND inside a structured filter.

Since the filter is applied on every keystroke, an incomplete expression SHALL
NOT empty the list: a missing closing parenthesis SHALL be implied, a trailing
operator and a field with no value SHALL be ignored, and a field value that
cannot be understood SHALL be ignored. The status line SHALL show how the filter
was understood, with its operators and grouping made explicit, and SHALL name
any term it ignored.

#### Scenario: A port that is open
- **WHEN** the user filters the host list with `open:22`
- **THEN** exactly the hosts with port 22 open are listed, and a host whose address contains `22` but has no open port 22 is not

#### Scenario: A port seen not open
- **WHEN** the user filters with `closed:443/tcp`
- **THEN** hosts on which 443/tcp was recorded closed or filtered are listed, and hosts on which it was never scanned are not

#### Scenario: Service and product
- **WHEN** the user filters with `service:http product:nginx`
- **THEN** hosts with a port whose service is http-like and whose product is nginx are listed

#### Scenario: AND ties field terms to one port
- **WHEN** a host runs http served by Apache on port 80 and ssh served by OpenSSH on port 22, and the user filters with `service:http AND product:openssh`
- **THEN** the host is not listed, because no single port is both; with `service:http AND product:apache` it is

#### Scenario: OR
- **WHEN** the user filters with `service:ssh OR service:telnet`
- **THEN** hosts offering either are listed

#### Scenario: NOT means none of the ports
- **WHEN** the user filters with `NOT service:ssh`
- **THEN** only hosts with no ssh port are listed, even if they have other ports

#### Scenario: Grouping
- **WHEN** the user filters with `service:http AND NOT (product:apache | product:iis)`
- **THEN** hosts with an http port and no port served by Apache or IIS are listed

#### Scenario: Structured and plain terms together
- **WHEN** the user filters with `10.0.0.0/24 open:445 !printer`
- **THEN** hosts in that range, with 445 open, and not fuzzy-matching `printer` are listed

#### Scenario: A plain filter is unchanged
- **WHEN** the user filters with `apache !ssl 10.0.0.0/8 192.168.0.0/16`
- **THEN** the result is exactly what it was before this change

#### Scenario: Port rows are filtered by their own port
- **WHEN** a host's port list is filtered with `service:ssh OR open:80`
- **THEN** only its ssh port, and port 80 if it is open, are listed

#### Scenario: Lowercase words are search words
- **WHEN** the user filters with `rock and roll`
- **THEN** it is three fuzzy terms, not an operator

#### Scenario: An unknown key is text
- **WHEN** the user filters with `http://intranet`
- **THEN** it is matched as text, not as a field

#### Scenario: Typing an incomplete query
- **WHEN** the user has typed `service:ssh OR (open:22` and not yet closed the parenthesis
- **THEN** the list shows what the completed expression would, and the status line shows the expression with the parenthesis closed

#### Scenario: A field without a value while typing
- **WHEN** the user has typed `service:`
- **THEN** the list is not emptied, and the status line says the term is being ignored

#### Scenario: An invalid port
- **WHEN** the user filters with `open:web`
- **THEN** the term is ignored and named in the status line as not understood

#### Scenario: Matches are still highlighted
- **WHEN** the user filters with `apache OR nginx`
- **THEN** the characters matching whichever term a row matched on are highlighted
