description: >-
  HostPath volumes let Pods use host directories and volumes in containers.
  Using host resources can be used to access shared data or escalate privileges
  and should not be allowed. This policy ensures no hostPath volumes are in use.

  validate:
    message: >-
       HostPath volumes are forbidden. The field spec.volumes[*].hostPath must be unset.
    pattern:
        spec:
            =(volumes):
              - X(hostPath): "null"
