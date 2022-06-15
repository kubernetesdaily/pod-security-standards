```
  name: disallow-capabilities-strict
  Disallow Capabilities (Strict)
   Pod Security Standards (Restricted)
  
   description: >-
      Adding capabilities other than `NET_BIND_SERVICE` is disallowed. In addition,
      all containers must explicitly drop `ALL` capabilities.

  rules:
    - name: require-drop-all
  
      preconditions:
        all:
        - key: "{{ request.operation }}"
          operator: NotEquals
          value: DELETE
      validate:
        message: >-
          Containers must drop `ALL` capabilities.
        foreach:
          - list: request.object.spec.[ephemeralContainers, initContainers, containers][]
            deny:
              conditions:
                all:
                - key: ALL
                  operator: AnyNotIn
                  value: "{{ element.securityContext.capabilities.drop || '' }}"
    - name: adding-capabilities-strict
      match:
        any:
        - resources:
            kinds:
              - Pod
      preconditions:
        all:
        - key: "{{ request.operation }}"
          operator: NotEquals
          value: DELETE
      validate:
        message: >-
          Any capabilities added other than NET_BIND_SERVICE are disallowed.
        foreach:
          - list: request.object.spec.[ephemeralContainers, initContainers, containers][]
            deny:
              conditions:
                all:
                - key: "{{ element.securityContext.capabilities.add[] || '' }}"
                  operator: AnyNotIn
                  value:
                  - NET_BIND_SERVICE
                  - ''
```                  