
  name: restrict-apparmor-profiles

description: >-
      On supported hosts, the 'runtime/default' AppArmor profile is applied by default.
      The default policy should prevent overriding or disabling the policy, or restrict
      overrides to an allowed set of profiles. This policy ensures Pods do not
      specify any other AppArmor profiles than `runtime/default` or `localhost/*`.

    - name: app-armor

      validate:
        message: >-
          Specifying other AppArmor profiles is disallowed. The annotation
          `container.apparmor.security.beta.kubernetes.io` if defined
          must not be set to anything other than `runtime/default` or `localhost/*`.
        pattern:
          =(metadata):
            =(annotations):
              =(container.apparmor.security.beta.kubernetes.io/*): "runtime/default | localhost/*"
