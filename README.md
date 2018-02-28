# helm-api-registrator
Simple Helm hook that can be used to generate TLS certificates and setup an aggregated API server accordingly

## Why ?
Because it is tricky to do correctly. Here are the step taken
- Create a certificate authority
- Create an https certificate valid for <service-name>.<namespace>.svc dns name
- Create a secret containing those materials
- Create the API Aggregation config, including the CA public key in a PEM format