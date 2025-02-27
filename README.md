# k8s\_crlish\_authorizer
_Kubernetes authorizer for denying specific credential IDs ("CRLish")_


## Introduction
For [almost a decade](https://github.com/kubernetes/kubernetes/issues/18982), the Kubernetes
has been pondering over how to best implement revocation checks for X.509 certificates.
Meanwhile, there has been no way to prevent compromised user/node certificate keys from being used
for malicious authentication.  
  
In Kubernetes version 1.32,
a [feature was merged](https://github.com/kubernetes/kubernetes/pull/125634) in the X.509
authenticator which adds a "credential ID" (SHA256 digest of client's certificate) to the
"UserInfo" object. A similar feature for service account tokens was also marked as GA in the same
release. At the time of writing, there doesn't seem to exist
[much documentation](https://github.com/kubernetes/website/pull/47715), but the features seem to
be targeted towards audit logging. Google Cloud has published a
[blog post](https://cloud.google.com/kubernetes-engine/docs/how-to/verify-identity-issuance-usage)
which demonstrates usage.  
  
Luckily, the "UserInfo" object is also available for authorizers. This enables usage of a
[custom WebHook authorizer](https://kubernetes.io/docs/reference/access-authn-authz/webhook/) that
validates credential IDs against a user-supplied deny list.  
  
This repository contains an implementation of such as custom authorizer and some guidance covering
how to use it!


## Current status
Proof of concept - beware of rough edges and limitations. Review the project's
[open issues](https://github.com/menacit/k8s_crlish_authorizer/issues?q=is%3Aissue%20state%3Aopen).


## Example usage
Generating a "credential ID" for a certificate file:

```
$ echo "X509SHA256=$(openssl x509 -in /var/lib/kubelet/pki/kubelet-client-current.pem -outform der | sha256sum | cut -d ' ' -f 1)"
```

Response from API server when a request is performed using a deny-listed credential ID:

```json
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {},
  "status": "Failure",
  "message": "forbidden: User \"system:node:worker-1\" cannot get path \"/api\": Credential ID \"X509SHA256=474d0c910180b290210fcba55f6f40054cd7d4a50b476bb1cce87796d899e948\" is included in deny list (\"CRLish\")",
  "reason": "Forbidden",
  "details": {},
  "code": 403
}
```

Matching log entry from k8s\_crlish\_authorizer application:

```json
{
  "time": "2025-02-27T13:16:30.156631908Z",
  "level": "WARN",
  "msg": "Subject access review data contains credential ID included in deny list",
  "credential-id": "X509SHA256=474d0c910180b290210fcba55f6f40054cd7d4a50b476bb1cce87796d899e948",
  "uid": "",
  "user": "system:node:worker-1",
  "groups": [
    "system:nodes",
    "system:authenticated"
  ]
}
````
