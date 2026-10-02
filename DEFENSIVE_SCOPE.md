# Defensive scope

Use only on local configuration snapshots whose owner authorizes inspection.
NginxConfigGuard helps maintainers review four documented static HTTP configuration
patterns and locate supporting directives without copying sensitive values into
reports. It does not generate exploitation requests, perform active discovery,
read includes/secret files, start Nginx, send traffic or alter configurations.

PASS is scoped to the frozen static policies, FAIL is a demonstrated policy pattern,
and OPEN is a coverage/semantic/intent gap. Scope/routing and variable observations
do not prove an actual request reaches a directive, that a filesystem object
exists, that authentication succeeds, or that a proxy connects to any destination.
Provider acceptance, applicant identity/organization/authorization and real-world
safeguard impact must be established separately. They remain OPEN here.

No header-security rules are implemented; all unselected Gixy performance/security
plugins remain UNIMPLEMENTED. README identifies exact supported grammar, selected
rule semantics, no-include behavior, finite variable model and unknown cases.
