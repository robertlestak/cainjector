# cainjector

`cainjector` is a Kubernetes Mutating Webhook that injects a CA certificate into all pods in the cluster. The CA certificate is mounted as a volume and can be used by applications to validate TLS connections in instances where the CA certificate is not available in the container image and you are unable to use service mesh sidecar TLS, such as when you have workloads outside of the service mesh.

In addition to injecting the CA certificate chain, `cainjector` also sets a `SSL_CERT_FILE` environment variable in the pod to the path of the CA certificate chain file. This allows applications to automatically use the CA certificate chain file without any additional configuration.

## Installation

Before installing `cainjector`, you must first have `cert-manager` deployed in your cluster. If you do not already have `cert-manager` deployed, you can follow the [installation instructions](https://cert-manager.io/docs/installation/) to deploy it.

### CA Cert Bundle

`cainjector` is designed to be used in conjunction with a larger PKI footprint, where the CA cert bundle is already deployed in every namespace in the cluster, either as a ConfigMap or a Secret. This can be done with [`trust-manager`](https://cert-manager.io/docs/projects/trust-manager/), [`cert-manager`](https://cert-manager.io/docs/) in combination with [`kubernetes-replicator`](https://github.com/mittwald/kubernetes-replicator), or any other method of your choosing.

For this example, we will be using [`trust-manager`](https://cert-manager.io/docs/projects/trust-manager/).

#### Create a CA Cert Bundle

```yaml
---
apiVersion: trust.cert-manager.io/v1alpha1
kind: Bundle
metadata:
  name: my-org.com
spec:
  sources:
  - useDefaultCAs: true
  - secret:
      name: "my-org.com-ca"
      key: "ca.crt"
  target:
    configMap:
      key: "ca.crt"
    additionalFormats:
      jks:
        key: "bundle.jks"
```

Applying the above `Bundle` to the cluster will create a `ConfigMap` named `my-org.com` in every namespace in the cluster. The `ConfigMap` will contain the CA cert bundle in PEM format, as well as a JKS format for use with Java applications. This will use the default CA cert bundle from the cluster, as well as the CA cert bundle from the `Secret` named `my-org.com-ca` in the `cert-manager` namespace, allowing us to inject our own CA cert bundle along with the default CA cert bundle.

Now that we have our CA cert bundle deployed, we can deploy `cainjector` to inject the CA cert bundle into all pods in the cluster.

### Configure `cainjector`

Edit `manifests/configmap.yaml` and change the `configMap` field to match the name of the `ConfigMap` you created in the previous step.  Optionally, you can also specify a different `mountPath` and `certFile` if you want to mount the CA cert bundle in a different location or use a different filename.

```yaml
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: cainjector-config
  namespace: cert-manager
data:
  config.yaml: |
    configMap: my-org.com
    mountPath: /cacerts
    certFile: ca.crt
    excludeContainers:
    - istio-proxy
    excludeNamespaces:
    - kube-system
    - cert-manager
    - istio-system
    includeNamespaces:
    - default
```

`configMap` is the name of the `ConfigMap` in every namespace that contains the CA cert bundle. You can also use a `Secret` instead of a `ConfigMap` by changing the `configMap` field to `secret` and specifying the name of the `Secret` in the `secret` field. These cannot be used together, so you must choose one or the other.

`mountPath` is the path where the CA cert bundle will be mounted in the pod. The default value is `/cacerts`.

`certFile` is the name of the CA cert bundle file. The default value is `ca.crt`.

The `excludeContainers` and `excludeNamespaces` fields can be used to exclude injection in specific containers or namespaces. This is useful if you have workloads that are already using service mesh sidecar TLS and you do not want to inject the CA cert bundle into those workloads.

The `includeNamespaces` field can be used to limit injection to specific namespaces. By default, the webhook will inject the CA cert bundle into all pods across all namespaces, except for those in the `excludeNamespaces` list. If you specify an `includeNamespaces` list, the webhook will only inject the CA cert bundle into pods in the namespaces specified in the `includeNamespaces` list, taking precedence over the `excludeNamespaces` list.

### Deploy `cainjector`

`cainjector` is deployed using vanilla Kubernetes manifests, found in the `manifests` directory.

Optionally, for white-labeling of the operator, you can edit `manifests/deployment.yaml` and change the `OPERATOR_NAME` and `OPERATOR_DOMAIN` environment variables to match your organization. These values will be used in the pod-specific annotations to override the global config. For example, if you set `OPERATOR_NAME` to `hello-world` and `OPERATOR_DOMAIN` to `my-org.com`, the pod-specific annotations would be `hello-world.my-org.com/inject`, `hello-world.my-org.com/secret`, etc.

```bash
kubectl apply -f manifests/
```

## Usage

Once `cainjector` is deployed, it will automatically inject the CA cert bundle into all pods in the cluster. You can verify that the CA cert bundle is being injected by checking the logs of the `cainjector` pod.

```bash
kubectl logs -n cert-manager -l app=cainjector
```

You can also check a pod to verify that the CA cert bundle is being injected.

```bash
kubectl exec -it -n default <pod> -- ls /cacerts
```

## Pod Annotations

By default, `cainjector` is configured globally with a config yaml file (deployed as a ConfigMap). This global config can be overridden on a per-pod basis by adding annotations to the pod spec.

```yaml
    annotations: 
      cainjector.lestak.sh/inject: "true" # default is "true", set to "false" to exclude injection
      cainjector.lestak.sh/secret: "my-cacert" # either secret or configMap must be specified
      cainjector.lestak.sh/configMap: "my-org.com" # either secret or configMap must be specified
      cainjector.lestak.sh/mountPath: "/cacerts"
      cainjector.lestak.sh/certFile: "ca.crt"
      cainjector.lestak.sh/excludeContainers: "istio-proxy"
      cainjector.lestak.sh/excludeNamespaces: "kube-system,cert-manager,istio-system"
      cainjector.lestak.sh/setEnvVar: "true" # default is "true", set to "false" to exclude setting the SSL_CERT_FILE environment variable
```