```
  name: restrict-seccomp-strict

   Restrict Seccomp (Strict)
  Pod Security Standards (Restricted)
    medium

description: >-
      The seccomp profile in the Restricted group must not be explicitly set to Unconfined
      but additionally must also not allow an unset value. This policy, 
      requiring Kubernetes v1.19 or later, ensures that seccomp is 
      set to `RuntimeDefault` or `Localhost`. A known issue prevents a policy such as this
      using `anyPattern` from being persisted properly in Kubernetes 1.23.0-1.23.2.

  rules:
    - name: check-seccomp-strict
   
      validate:
        message: >-
          Use of custom Seccomp profiles is disallowed. The fields
          spec.securityContext.seccompProfile.type,
          spec.containers[*].securityContext.seccompProfile.type,
          spec.initContainers[*].securityContext.seccompProfile.type, and
          spec.ephemeralContainers[*].securityContext.seccompProfile.type
          must be set to `RuntimeDefault` or `Localhost`.
        anyPattern:
        - spec:
            securityContext:
              seccompProfile:
                type: "RuntimeDefault | Localhost"
            =(ephemeralContainers):
            - =(securityContext):
                =(seccompProfile):
                  =(type): "RuntimeDefault | Localhost"
            =(initContainers):
            - =(securityContext):
                =(seccompProfile):
                  =(type): "RuntimeDefault | Localhost"
            containers:
            - =(securityContext):
                =(seccompProfile):
                  =(type): "RuntimeDefault | Localhost"
        - spec:
            =(ephemeralContainers):
            - securityContext:
                seccompProfile:
                  type: "RuntimeDefault | Localhost"
            =(initContainers):
            - securityContext:
                seccompProfile:
                  type: "RuntimeDefault | Localhost"
            containers:
            - securityContext:
                seccompProfile:
                  type: "RuntimeDefault | Localhost"
```