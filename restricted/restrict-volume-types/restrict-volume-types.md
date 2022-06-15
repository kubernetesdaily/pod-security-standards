```
description: >-
      In addition to restricting HostPath volumes, the restricted pod security profile
      limits usage of non-core volume types to those defined through PersistentVolumes.
      This policy blocks any other type of volume other than those in the allow list.
spec:
  validationFailureAction: audit
  background: true
  rules:
    - name: restricted-volumes
      match:
        any:
        - resources:
            kinds:
              - Pod
      validate:
        message: >-
          Only the following types of volumes may be used: configMap, csi, downwardAPI,
          emptyDir, ephemeral, persistentVolumeClaim, projected, and secret.
        deny:
          conditions:
            all:
            - key: "{{ request.object.spec.volumes[].keys(@)[] || '' }}"
              operator: AnyNotIn
              value:
              - name
              - configMap
              - csi
              - downwardAPI
              - emptyDir
              - ephemeral
              - persistentVolumeClaim
              - projected
              - secret
              - ''
              ```