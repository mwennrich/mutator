#! /bin/bash

# Create certs for our webhook
openssl genrsa -out webhookCA.key 2048
openssl req -new -key webhookCA.key -subj "/CN=pod-mutator.default.svc"  -out webhookCA.csr
openssl x509 -req -days 3650 -in webhookCA.csr -signkey webhookCA.key -out webhook.crt -extfile csr.ext

# Create certs secrets for k8s
kubectl create secret generic \
    pod-mutator-certs \
    --from-file=key.pem=webhookCA.key \
    --from-file=cert.pem=webhook.crt \
    --dry-run=client -o yaml > webhook-certs.yaml

# Set the CABundle on the webhook registration
CA_BUNDLE=$(base64 -w0 < webhook.crt)
sed "s/CA_BUNDLE/${CA_BUNDLE}/" webhook-registration.yaml.tpl > webhook-registration.yaml

# Clean
rm webhookCA* && rm webhook.crt
