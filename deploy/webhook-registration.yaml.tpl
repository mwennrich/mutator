apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: mutator
webhooks:
- admissionReviewVersions:
  - v1beta1
  clientConfig:
    caBundle: CA_BUNDLE
    service:
      name: mutator
      namespace: default
      port: 443
  failurePolicy: Ignore
  matchPolicy: Exact
  name: mutator.metal-stack.dev
  namespaceSelector: {}
  objectSelector: {}
  rules:
  - apiGroups:
    - apps
    apiVersions:
    - v1
    operations:
    - CREATE
    - UPDATE
    resources:
    - deployments
    - statefulsets
    scope: '*'
  sideEffects: None
