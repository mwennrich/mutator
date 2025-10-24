# generic mutator using json patch

A small rule-based kubernetes object mutator, which can mutate generic kubernetes objects based on json patch rules.

## Example

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: mutator-rules
data:
  rules.json: |
    {
      "rules": [
        {
          "namespace": ^(default)$",
          name": "^(demo1)$",
          kind": "^(StatefulSet)$",
          "patch": "[{\"op\": \"add\", \"path\": \"/spec/template/metadata/labels/mwen\", \"value\": \"test2\"}]"
        },
        {
          "namespace": ^(default)$",
          name": "^(demo2)$",
          kind": "^(Deployment)$",
          "patch": "[{\"op\": \"add\", \"path\": \"/spec/template/spec/containers/0/command/-\", \"value\": \"--test=true\"}]"
        },
        {
          "namespace": "^(kube-system)$",
          "name": "^(metrics-server)$",
          "kind": "^(Deployment)$",
          "patch": "[{\"op\": \"replace\", \"path\": \"/spec/template/spec/containers/0/image\", \"value\": \"registry.k8s.io/metrics-server/metrics-server:v0.5.2\"}]"
        }
      ]
    }
```

## Configuration

### Log Level

The log level can be configured using the `LOG_LEVEL` environment variable.

**Default:** `error` (only errors are logged)

**Available levels:** `panic`, `fatal`, `error`, `warn`, `info`, `debug`, `trace`

