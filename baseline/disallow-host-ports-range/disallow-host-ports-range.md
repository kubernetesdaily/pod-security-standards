  name: disallow-host-ports-range
  description: >-
      Access to host ports allows potential snooping of network traffic and should not be
      allowed, or at minimum restricted to a known list. This policy ensures the `hostPort`
      field is set to one in the designated list. 

    - name: host-port-range

      validate:
        message: >-
          The only permitted hostPorts are in the range 5000-6000.
        deny:
          conditions:
            all:
            - key: "{{ request.object.spec.[ephemeralContainers, initContainers, containers][].ports[].hostPort }}"
              operator: AnyNotIn
              value: 5000-6000