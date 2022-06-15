```
  name: disallow-proc-mount
  description: >-
      The default /proc masks are set up to reduce attack surface and should be required. This policy
      ensures nothing but the default procMount can be specified. Note that in order for users
      to deviate from the `Default` procMount requires setting a feature gate at the API
      server.

      validate:
        message: >-
          Changing the proc mount from the default is not allowed. The fields
          spec.containers[*].securityContext.procMount, spec.initContainers[*].securityContext.procMount,
          and spec.ephemeralContainers[*].securityContext.procMount must be unset or
          set to `Default`.
        pattern:
          spec:
            =(ephemeralContainers):
              - =(securityContext):
                  =(procMount): "Default"
            =(initContainers):
              - =(securityContext):
                  =(procMount): "Default"
            containers:
              - =(securityContext):
                  =(procMount): "Default"
```