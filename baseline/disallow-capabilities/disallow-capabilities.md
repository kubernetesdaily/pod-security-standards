  ```
  name: disallow-capabilities
  Adding capabilities beyond those listed in the policy must be disallowed.
  validate:
        message: >-
          Any capabilities added beyond the allowed list (AUDIT_WRITE, CHOWN, DAC_OVERRIDE, FOWNER,
          FSETID, KILL, MKNOD, NET_BIND_SERVICE, SETFCAP, SETGID, SETPCAP, SETUID, SYS_CHROOT)
          are disallowed.
        deny:
          conditions:
            all:
             value:
              - AUDIT_WRITE
              - CHOWN
              - DAC_OVERRIDE
              - FOWNER
              - FSETID
              - KILL
              - MKNOD
              - NET_BIND_SERVICE
              - SETFCAP
              - SETGID
              - SETPCAP
              - SETUID
              - SYS_CHROOT
```