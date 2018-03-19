# Cloudforms VAULT Bridge

This code was developed to manage VAULT Secrets in Cloudforms / ManageIQ Statemachine Domains / Code.

```
docker run -i --rm -e VAULT_TOKEN=$VAULT_TOKEN -v `pwd`:/usr/src/app/data cloudforms-vault-bridge:local
```

