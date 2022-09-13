# pod security standards 


## apply to namespace level  
```
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: my-baseline-namespace
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: baseline
    pod-security.kubernetes.io/warn-version: latest
  # We are setting these to our _desired_ `enforce` <span class='kc-markdown-code-copy'></span> level.
    pod-security.kubernetes.io/audit: baseline
    pod-security.kubernetes.io/audit-version: latest
  
---
apiVersion: v1
kind: Namespace
metadata:
  name: my-restricted-namespace
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: latest
    pod-security.kubernetes.io/audit:  restricted
    pod-security.kubernetes.io/audit-version: latest
EOF
```

```
cd baseline 
```

## create pod on baseline namespace 

```
 kubectl apply -f resource.yaml --namespace=my-baseline-namespace
 ```

## create pod on restricted namespace 

change dir

```
cd restricted 
```

```
 kubectl apply -f resource.yaml --namespace=my-restricted-namespace 
 ```


check it out :- https://github.com/sangam14/pod-security-standards

 
