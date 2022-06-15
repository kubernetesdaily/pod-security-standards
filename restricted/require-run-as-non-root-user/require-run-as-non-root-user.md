```
  name: require-run-as-non-root-user
  Require Run As Non-Root User
   Pod Security Standards (Restricted)
description: >-
      Containers must be required to run as non-root users. This policy ensures
      `runAsUser` is either unset or set to a number greater than zero.
rules:
    - name: run-as-non-root-user
  
validate:
        message: >-
          Running as root is not allowed. The fields spec.securityContext.runAsUser,
          spec.containers[*].securityContext.runAsUser, spec.initContainers[*].securityContext.runAsUser,
          and spec.ephemeralContainers[*].securityContext.runAsUser must be unset or
          set to a number greater than zero.
        pattern:
          spec:
            =(securityContext):
              =(runAsUser): ">0"
            =(ephemeralContainers):
            - =(securityContext):
                =(runAsUser): ">0"
            =(initContainers):
            - =(securityContext):
                =(runAsUser): ">0"
            containers:
            - =(securityContext):
                =(runAsUser): ">0"
```