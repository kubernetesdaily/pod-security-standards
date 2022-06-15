
```
name: disallow-host-namespaces
   Host namespaces (Process ID namespace, Inter-Process Communication namespace, and
   network namespace) allow access to shared information and can be used to elevate
   privileges. Pods should not be allowed access to host namespaces. This policy ensures
   fields which make use of these host namespaces are unset or set to `false`.
validate:
    message: >-
      Sharing the host namespaces is disallowed. The fields spec.hostNetwork,
      spec.hostIPC, and spec.hostPID must be unset or set to `false`.
      pattern:
          spec:
            =(hostPID): "false"
            =(hostIPC): "false"
            =(hostNetwork): "false"
```