#!/usr/bin/env nu
 
(
    nu ./nucert.nu
        --verbose
        --debug-save-response
        --staging
        --use-exixting-account
        --write-log
        --show-extra-log
        # --dir-uri 'https://0.0.0.0:14000/dir'
        --domain 'example.com, *.example.com'
)
