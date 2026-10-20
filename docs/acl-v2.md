# ACL v2

A v2 ACL is one flat list of rules. Smokescreen loads it when the file has
`version: v2`. v1 files keep working: smokescreen translates them into v2 and
decides with the same engine.

```yaml
version: v2
roles:
  - {name: ci, project: ci-infra, mode: open, proxies: [proxy.example.net]}
unknown_role: {project: unknown, mode: enforce}
rules:
  - id: deny-package-registries
    action: deny
    subjects: {any: true}
    domains: [pypi.org, {glob: "regis*.npmjs.org", cross_public_suffix: true}]
  - id: ci-registries
    action: allow
    subjects: {roles: [ci]}
    domains: [pypi.org]
    overrides: [deny-package-registries]
```

Decision order:

1. A role that is not listed uses `unknown_role`, or is denied if there is none.
2. A CONNECT proxy host must match one of the role's `proxies`.
3. Rules for the role decide first, then rules for `any`. Inside each, deny wins.
4. If no rule matches, the role's `mode` decides.

A role allow that overlaps an `any` deny must name it in `overrides`.
