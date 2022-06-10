
  name: restrict-seccomp
  description: >-
      The seccomp profile must not be explicitly set to Unconfined. This policy, 
      requiring Kubernetes v1.19 or later, ensures that seccomp is unset or 
      set to `RuntimeDefault` or `Localhost`.
 name: check-seccomp
 validate:
        message: >-
          Use of custom Seccomp profiles is disallowed. The fields
          spec.securityContext.seccompProfile.type,
          spec.containers[*].securityContext.seccompProfile.type,
          spec.initContainers[*].securityContext.seccompProfile.type, and
          spec.ephemeralContainers[*].securityContext.seccompProfile.type
          must be unset or set to `RuntimeDefault` or `Localhost`.
        pattern:
          spec:
            =(securityContext):
              =(seccompProfile):
                =(type): "RuntimeDefault | Localhost"      
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
