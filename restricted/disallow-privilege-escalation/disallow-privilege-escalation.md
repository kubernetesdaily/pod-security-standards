
  name: disallow-privilege-escalation
  description: >-
      Privilege escalation, such as via set-user-ID or set-group-ID file mode, should not be allowed.
      This policy ensures the `allowPrivilegeEscalation` field is set to `false`.

  rules:
    - name: privilege-escalation
   
      validate:
        message: >-
          Privilege escalation is disallowed. The fields
          spec.containers[*].securityContext.allowPrivilegeEscalation,
          spec.initContainers[*].securityContext.allowPrivilegeEscalation,
          and spec.ephemeralContainers[*].securityContext.allowPrivilegeEscalation
          must be set to `false`.
        pattern:
          spec:
            =(ephemeralContainers):
            - securityContext:
                allowPrivilegeEscalation: "false"
            =(initContainers):
            - securityContext:
                allowPrivilegeEscalation: "false"
            containers:
            - securityContext:
                allowPrivilegeEscalation: "false"
