# Nucert

Self documenting nushell script to issue and renew TLS certs from Let's Encrypt 

![[_assets/nucert-example.webp]]

## Usage

To generate new certificate

```sh
./nucert.nu --domain 'example.com, *.example.com'
```

To generate new staging certificate

  
```sh
./nucert.nu --domain --staging 'example.com, *.example.com'
```