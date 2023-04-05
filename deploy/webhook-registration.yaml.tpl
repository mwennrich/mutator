apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: pod-mutator
webhooks:
- admissionReviewVersions:
  - v1beta1
  clientConfig:
    caBundle: CA_BUNDLE
    service:
      name: pod-mutator
      namespace: default
      port: 443
  failurePolicy: Ignore
  matchPolicy: Exact
  name: pod-mutator.metal-stack.dev
  namespaceSelector: {}
  objectSelector: {}
  rules:
  - apiGroups:
    - ""
    apiVersions:
    - v1
    operations:
    - CREATE
    resources:
    - pods
    scope: '*'
  sideEffects: None
