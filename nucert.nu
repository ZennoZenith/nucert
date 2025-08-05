#!/usr/bin/env nu

# openssl >= 1.1.1 required (no openssl config file needed)
 
let START_TIME = (date now | format-timestamp)

const DEFAULT_CFG = {
    LOG_LEVEL: 1
    FILE_LOG_LEVEL: 0
    CONFIG_TOML: "./config.toml"
    NONCE_CACHE_FILE: "./run/nonceCacheQueue.toml" 
    WRITE_LOG: true
    SHOW_EXTRA_LOG: true
    MAX_TIMEOUT_DURATION: 4sec 
    USE_EXISTING_ACCOUNT: false
    DIR_URI: ""

    PRIVATE_KEY_FILE_NAME: 'account_private.pem'
    PUBLIC_KEY_FILE_NAME: 'account_pub.pem'
    DOMAIN_KEY_FILE_NAME: 'domain_private.pem'

    NONCE_RETRIES: 3
    NONCE_RETRIES_SLEEP_DURATION: 2sec
    
    STAGING: false
    AGREE_TOS: true

    ## TODO: add script version see [RFC7231]
    ## TODO: add accep language header [RFC7231]
    HEADERS: {
      "User-Agent": "nucert"
    }

    ## DIRS
    LOG_DIR: $"./log"
    RUN_DIR: "./run"
    ACME: {
        # ACME API uris
        PRODUCTION_URL: "https://acme-v02.api.letsencrypt.org/directory"
        STAGING_URI: "https://acme-staging-v02.api.letsencrypt.org/directory"
    }

    # DEBUG: remove this in production
    DEBUG_SAVE_RESPONSE: false
}

#######################################################
### LOGGING FUNCTIONS
#######################################################
 
module log {
    def log [CFG:record typ: string, message:string, extra: record = {}] {
        let now = (date now | format-timestamp-rfc-short )
        let meta = match ($typ | str downcase) {
            "debug" => {level: 1 typ: "debug" short: "DBG" ansi: "dark_gray"}
            "info" => {level: 2 typ: "info" short: "INF" ansi: "light_gray"}
            "warn" => {level: 3 typ: "warning" short: "WRN" ansi: "yellow"}
            "err" => {level: 4 typ: "error" short: "ERR" ansi: "red"}
            "critical" => {level: 5 typ: "critical" short: "CRT" ansi: "red_bold"}
            _ => {level: 2 typ: "other" short: "OTH" ansi: "white"}
        }

        if $meta.level > $CFG.LOG_LEVEL {
            let extra = if ($extra == {} or not $CFG.SHOW_EXTRA_LOG) { "" } else { $extra | to-json-raw | $" [($in)]"}
            print $"(ansi $meta.ansi)($now) [($meta.short)] ($message)($extra)(ansi reset)"
        }
                
        if ($CFG.WRITE_LOG and $meta.level > $CFG.FILE_LOG_LEVEL) {
            (
                {
                    ts: $now
                    level: $meta.typ
                    msg: $message
                    extra: $extra
                }
                | to-json-raw
                | $"($in)\n" 
                | save --append $"($CFG.LOG_DIR)/($START_TIME).log"
            )
            
        }

        null
    }

    export def debug [CFG:record message: string = "" extra: record = {}] {
      log $CFG "debug" $message $extra
    }

    export def info [CFG:record message: string = "" extra: record = {}] {
      log $CFG "info" $message $extra
    }

    export def warn [CFG:record message: string = "" extra: record = {}] {
      log $CFG "warn" $message $extra
    }

    export def err [CFG:record message: string = "" extra: record = {}] {
      log $CFG "err" $message $extra
    }

    export def critical [CFG:record message: string = "" extra: record = {}] {
      log $CFG "critical" $message $extra
    }
}

use log *

#######################################################
### Utils
#######################################################
 
def encode-base64-nopad-url []: any -> string {
    $in | encode base64 --nopad --url
}

def to-json-raw []: any -> string {
    $in | to json --raw --serialize
}

def format-timestamp []: datetime -> string {
    return ($in | format date "%FT%H.%M.%S%.3f")
}

## ISO 8601 / RFC 3339 date & time format.
def format-timestamp-rfc []: datetime  -> string {
    return ($in | format date "%+")
}

def format-timestamp-rfc-short []: datetime  -> string {
    return ($in | format-timestamp-rfc | split chars | take 23 | append 'Z' | str join "")
}

def is-config-exist [CFG: record]: nothing -> string {
    if not ($CFG.CONFIG_TOML | path exists ) {
        return $"($CFG.CONFIG_TOML) does not exixts"
    }

    if (($CFG.CONFIG_TOML | path type) != 'file' ) {
        return $"($CFG.CONFIG_TOML) is not a file"
    }

    "true"
}

def read-config [CFG: record] {
    let does_exist = (is-config-exist $CFG)
    if ($does_exist != 'true') {
        critical $CFG $does_exist
        exit 1
    }
    let data = open --raw $CFG.CONFIG_TOML | from toml
    $data
}

def verify-config [config: record] {
    if not ($config.private_key_file? | path exists) {
        return false
    }
    
    if not ($config.public_key_file? | path exists) {
        return false
    }
    
    if not ($config.domain_key_file? | path exists) {
        return false
    }
    
    return true
}

def write-config [CFG: record, value: record] {
    let data = (read-config $CFG | merge $value)
    $data | to toml | save -f $CFG.CONFIG_TOML
}

def write-initial-config [CFG: record, value: record] {
    $value | to toml | save -f $CFG.CONFIG_TOML
}

def extract-nonce [res: record] {
    let nonce = $res | get headers.response | where { $in.name == "replay-nonce"} | get value | first
    $nonce
}

def extract-header-value [res: record name: string] {
    let location = $res | get headers.response | where { $in.name == $name } | get value | first
    $location
}

def extract-location-header [res: record] {
    let location = (extract-header-value $res "location")
    $location
}

def generate-nonce-cache [
    CFG: record
]: nothing -> record<new_nonce: list<string> used_nonce: list<string>> {
    let emptyNonceCacheType = {
        new_nonce: []
        used_nonce: []
    }

    let cache_exists = ($CFG.NONCE_CACHE_FILE | path exists) and (($CFG.NONCE_CACHE_FILE | path type) == 'file')

    let cache = if $cache_exists {
        open $CFG.NONCE_CACHE_FILE
    } else {
        $emptyNonceCacheType | save -f $CFG.NONCE_CACHE_FILE
        open $CFG.NONCE_CACHE_FILE
    }

    $cache
}

def write-nonce-cache [
    CFG: record
    cache: record<new_nonce: list<string> used_nonce: list<string>>
]: nothing -> record<new_nonce: list<string> used_nonce: list<string>> {
    $cache | save -f $CFG.NONCE_CACHE_FILE
    open $CFG.NONCE_CACHE_FILE
}

def enqueue-nonce [CFG: record, nonce: string] {
    let cache = generate-nonce-cache $CFG

    let known_nonce = $cache.new_nonce | append $cache.used_nonce

    if not ($known_nonce | any { $in == $nonce}) {
        let new_nonces = ($cache.new_nonce | append $nonce)
        write-nonce-cache $CFG { new_nonce: $new_nonces used_nonce: $cache.used_nonce}
    }
}

def dequeue-nonce [CFG: record cache_uri: string] {
    let cache = generate-nonce-cache $CFG

    let nonce = if ($cache.new_nonce | is-empty) {
        let uri = $cache_uri
        debug $CFG $"Requesting nonce." { uri: $uri }
        info $CFG $"getting directory from url" { uri: $uri }

        ## DEBUG: remove insecure
        let res = http head --insecure --headers $CFG.HEADERS $uri

        ## Converting res to full response object
        let res = { headers: { "response": $res } }
        let nonce = extract-nonce $res
        $nonce
    } else {
        ($cache.new_nonce | first)
    }

    ## Removing dequed cache
    let new_nonces = ($cache.new_nonce | where {$in != $nonce})
    let used_nonce = ($cache.used_nonce | append $nonce | uniq)

    write-nonce-cache $CFG { new_nonce: $new_nonces used_nonce: $used_nonce}
    
    $nonce
}

def debug-save-all-response [CFG: record data: record] {
    let file = $"($CFG.LOG_DIR)/($START_TIME)_response.json"
    if not ($file | path exists) {
        [] | to-json-raw | save -f $file
    }

    let contents = open $file 

    let latest = ($contents | append $data)

    $latest | to json | save -f $file
}

def api-request [
    CFG: record 
    CTX: record # { jwk: { jwk: {...} or kid: "..." }, nonce?: "", HEADERS: {...}, private_key_file : "..."}
    uri: string
    body: any = {}
    retry: int = 0
] {
    if $retry > 0 {
        info $CFG $"Retry attempt ($retry)"
    }

    let body_type = $body | describe 
    if not (
        ($body_type | str starts-with 'record') or
        ($body_type == 'string')
    ) {
        critical $CFG $"body should be either record or stirng. got: ($body_type)"
        exit 1
    }

    let nonce = dequeue-nonce $CFG $CTX.acme.uri.newNonce 
    let headers = {
        ...$CFG.HEADERS
        'Content-Type': 'application/jose+json'
    }

    let jws_protected_headers = {
        alg: "RS256"
        url: $uri
        ...$CTX.jwk ## { jwk: '...'} or { kid: '...'}
        nonce: $nonce
    }


    let jws_protected = $jws_protected_headers | to-json-raw | encode-base64-nopad-url

    let jws_payload = if $body == '' {
        ''    
    } else {
        $body | to-json-raw | encode-base64-nopad-url
    }

    let jws_signature = (
        $"($jws_protected).($jws_payload)"
        | openssl dgst -sha256 -sign $CTX.private_key_file
        | encode-base64-nopad-url
    )

    let jws = {
        protected: $jws_protected
        payload: $jws_payload
        signature: $jws_signature
    }

    debug $CFG $"Request URL: ($uri)"
    # debug $CFG $"Body: --- " $body
    # debug $CFG $"Protected header: --- " $jws_protected_headers
    # debug $CFG $"JWS header: --- " { jws_protected: $jws_protected }
    # debug $CFG $"JWS payload: --- " { jws_payload: $jws_payload }
    # debug $CFG $"JWS signature: --- " { jws_signature: $jws_signature }

    let res = (
        http post
          --full
          --allow-errors
          --insecure ## DEBUG: Remove in production  
          --content-type 'application/jose+json'
          --headers $headers
          --max-time $CFG.MAX_TIMEOUT_DURATION
          $uri
          ($jws | to-json-raw)
    )

    let nonce = extract-nonce $res
    enqueue-nonce $CFG $nonce

    if $CFG.DEBUG_SAVE_RESPONSE {
        debug-save-all-response $CFG {
            request_uri: $uri
            request_body: $body
            response: $res
        }
        
    }

    if ($res | to-json-raw | str contains "urn:ietf:params:acme:error:badNonce") {
        warn $CFG "Expired nonce"

        if $retry < $CFG.NONCE_RETRIES {
            warn $CFG $"Retrying in ($CFG.NONCE_RETRIES_SLEEP_DURATION)"
            sleep $CFG.NONCE_RETRIES_SLEEP_DURATION
            let res = api-request $CFG $CTX $uri $body ($retry + 1)
            return $res
        } else {
            critical $CFG $"Max retry limit reached. Exiting ..."
            exit 1
        }
    }

    $res
}

def get-acme-directory [CFG: record] {
    let state = if ($CFG.DIR_URI | is-not-empty) {
      {server:'CUSTOM' url: $CFG.DIR_URI}
    } else if $CFG.STAGING {
      {server:'STAGING' url: $CFG.ACME.STAGING_URI}
    } else {
      {server:'PRODUCTION' url: $CFG.ACME.PRODUCTION_URL}
    }

    info $CFG $"getting directory from url: ($state.url)" $state
    let res = (
        http get
            --full
            --insecure ## DEBUG: Remove in production  
            --allow-errors
            --headers $CFG.HEADERS
            $state.url
    )

    $res
}

def get-acme-uri [res: record] {
  return {
    newAccount: $res.body.newAccount
    newNonce: $res.body.newNonce
    newOrder: $res.body.newOrder
    renewalInfo: $res.body.renewalInfo
    revokeCert: $res.body.revokeCert
    keyChange: $res.body.keyChange
    termsOfService: $res.body.meta.termsOfService
    website: $res.body.meta.website?
  }
}

def get-account-info [CFG:record CTX: record] {
    let does_config_exist = (is-config-exist $CFG)

    if ($does_config_exist != "true") {
        warn $CFG $"config file: ($CFG.CONFIG_TOML) does not exist. Creating new account"
        create-new-config $CFG $CTX
    } else {
        info $CFG $"Reading config from file: ($CFG.CONFIG_TOML)"
    }

    let config = read-config $CFG

    let is_valid_config = verify-config $config

    if not $is_valid_config {
        warn $CFG $"Config file exists but its values file does not exists"
        create-new-config $CFG $CTX
    }

    

    let account_id = ($config |  default "" account_id | get account_id)


    if ($account_id | is-not-empty) {
        let uri = $account_id

        let local_ctx = $CTX | merge {
            jwk: { kid: $account_id }
            private_key_file: $config.private_key_file
        }

        let res = api-request $CFG $local_ctx $uri ""

        if ($res | to-json-raw | str contains 'urn:ietf:params:acme:error:accountDoesNotExist') {
            warn $CFG "Account id defined in config does not exist. Creating new account"
        } else {
            return {
                account_id: $config.account_id
                private_key_file: $config.private_key_file
                public_key_file: $config.public_key_file
                domain_key_file: $config.domain_key_file
                jwk_thumbprint: $config.jwk_thumbprint
                jwk_public_key: $config.jwk_public_key
            }
        }
    } else {
        warn $CFG "Acme account does not exists"       
    }


    let CTX_WITH_CFG = {
        ...$CTX
        private_key_file: $config.private_key_file
        public_key_file: $config.public_key_file
        domain_key_file: $config.domain_key_file
        jwk_thumbprint: $config.jwk_thumbprint
        jwk_public_key: $config.jwk_public_key
    }

    let v =  register-new-account $CFG $CTX_WITH_CFG

    write-config $CFG {
        account_id: $v.account_id
    }

    return {
        account_id: $v.account_id
        private_key_file: $config.private_key_file
        public_key_file: $config.public_key_file
        domain_key_file: $config.domain_key_file
        jwk_thumbprint: $config.jwk_thumbprint
        jwk_public_key: $config.jwk_public_key
    }
    
}

def register-new-account [
    CFG:record
    CTX: record
]: nothing -> record<account_id: string nonce:string> {
    info $CFG "Registering new acme account..."

    let config = read-config $CFG
    let private_key_file = $config.private_key_file
    let public_key_file = $config.public_key_file

    mut body = { termsOfServiceAgreed: true }

    if ($CTX.emails | is-not-empty) {
        $body.contact = []
        for email in $CTX.emails {
            $body.contact ++= [$'mailto:($email)']
        }
    }

    debug $CFG $"Account registeration request body: ($body | to-json-raw)"

    let uri = $CTX.acme.uri.newAccount;
   
    let jwk_public_key = $CTX.jwk_public_key

    let local_ctx = $CTX | merge {
        # INFO:
        # API authentication by JWK until we have an account
        # only in registering acount phase JWK is jwk,
        # for other routes when acount is registered kid
        # will be used
        jwk: { jwk: $jwk_public_key}
        private_key_file: $CTX.private_key_file
    }

    let res = api-request $CFG $local_ctx $uri $body

    ## TODO: handle error return
    if ($res | to-json-raw | str contains 'urn:ietf:params:acme:error') {
        err $CFG "API error"
        err $CFG $"Response status: ($res.status)"
        err $CFG $"Response body: ($res.body)"
    }

    let account_id = extract-location-header $res

    info $CFG "Account registered"
    
    return {
        account_id: $account_id
    }
}

def create-new-config [CFG:record CTX: record] {
    mkdir $CFG.RUN_DIR

    try { rm $CFG.CONFIG_TOML }

    let private_key_file = $"($CFG.RUN_DIR)/($CFG.PRIVATE_KEY_FILE_NAME)"
    let public_key_file = $"($CFG.RUN_DIR)/($CFG.PUBLIC_KEY_FILE_NAME)"
    let domain_key_file = $"($CFG.RUN_DIR)/($CFG.DOMAIN_KEY_FILE_NAME)"

    mut is_error = false
    if ($private_key_file | path exists) {
        err $CFG $"($private_key_file) already exists. Try renaming existing file"
        $is_error = true
    }

    if ($public_key_file | path exists) {
        err $CFG $"($public_key_file) already exists. Try renaming existing file"
        $is_error = true
    }

    if ($domain_key_file | path exists) {
        err $CFG $"($domain_key_file) already exists. Try renaming existing file"
        $is_error = true
    }

    if not $is_error {
        generate-private-public-key $CFG
    }

    while $is_error {
        print "Please select what action to be taken:
    (1) Use existing keys
    (2) Create backup and generate new
    (3) Overwrite keys
    (4) Exit"
        let choice = if $CFG.USE_EXISTING_ACCOUNT {
            info $CFG "--use-existing flag set. auto selecting option"
            '1'      
        } else {
            input "Your selection? " | str trim
        }

        if not (['1' '2' '3' '4'] | any { $in == $choice}) {
            warn $CFG "Invalid selection."
            continue 
        }

        match $choice {
            '1' => {
                # TODO: check if existing files are correct format
                info $CFG "Using existing keys"
            },
            '2' => {
                # TODO: check if existing files are correct format
                info $CFG "Creating backup of existing keys"
                let t = (date now | format-timestamp)
                let private_key_file_backup = $"($private_key_file).($t).bak"
                let public_key_file_backup = $"($public_key_file).($t).bak"
                let domain_key_file_backup = $"($domain_key_file).($t).bak"

                mv $private_key_file $private_key_file_backup
                mv $public_key_file $public_key_file_backup
                mv $domain_key_file $domain_key_file_backup

                info $CFG $"Backup private key: ($private_key_file_backup)"
                info $CFG $"Backup public key: ($public_key_file_backup)" 
                info $CFG $"Backup domain key: ($domain_key_file_backup)" 

                generate-private-public-key $CFG
            },
            '3' => {
                let sure = input "Are you sure (y/N) " | str trim | str downcase

                if not ($sure == "Y" or $sure == "y") {
                    continue 
                }

                rm $private_key_file
                rm $public_key_file
                rm $domain_key_file

                generate-private-public-key $CFG
            },
            '4' => {
                info $CFG "Exiting..."
                exit 0
            },
        }
        break
    }
    
    let jwk = (generate-jwk-public-key $CFG $public_key_file)

    write-initial-config $CFG {
        private_key_file: $"($CFG.RUN_DIR)/($CFG.PRIVATE_KEY_FILE_NAME)"
        public_key_file: $"($CFG.RUN_DIR)/($CFG.PUBLIC_KEY_FILE_NAME)"
        domain_key_file: $"($CFG.RUN_DIR)/($CFG.DOMAIN_KEY_FILE_NAME)"
        ...$jwk
    }
}

def generate-jwk-public-key [CFG:record public_key_file: string]: nothing -> record {
    let public_key_text_hex = openssl rsa -pubin -in $public_key_file -text -noout

    let modulus = ( $public_key_text_hex
            | str replace --all ":" "" | str replace --all " " ""
            | lines | skip 2
            | take while {
                |v| not ($v | str starts-with "Exponent")
            }
            | str join "" | str trim --left --char '0'
        )
        | decode hex | encode-base64-nopad-url

    debug $CFG $"Modulus: ($modulus)"

    let exponent = ($public_key_text_hex
        | lines | last | split words | get 1
        | into int | into binary --compact | encode-base64-nopad-url)

    debug $CFG $"Exponent: ($exponent)"

    const key_type = "RSA"
    debug $CFG $"Key type: ($key_type)"
   
    # INFO:
    # API authentication by JWK until we have an account
    # only in registering acount phase JWK is jwk,
    # for other routes when acount is registered kid
    # will be used
    # TODO: check if it shoud really be named JWK or JWS
    let jwk = {
        e: $exponent  
        kty: $key_type  
        n: $modulus
    }

    # https://tools.ietf.org/html/rfc7638
    # IMPORTANT: TODO: to make sure key order is maintained
    let jwk_thumbprint = ( $jwk
        | to-json-raw
        | openssl dgst -sha256 -hex
        | split words | last
        | decode hex
        | encode-base64-nopad-url 
    )
  
    debug $CFG $"jwk_thumbprint: ($jwk_thumbprint)"

    return {
        jwk_public_key: $jwk
        jwk_thumbprint: $jwk_thumbprint
    }
}

def generate-private-public-key [CFG: record] {
    info $CFG "Generating new account key..."
    let private_key_file = $"($CFG.RUN_DIR)/($CFG.PRIVATE_KEY_FILE_NAME)"
    let public_key_file = $"($CFG.RUN_DIR)/($CFG.PUBLIC_KEY_FILE_NAME)"
    let domain_key_file = $"($CFG.RUN_DIR)/($CFG.DOMAIN_KEY_FILE_NAME)"


    openssl genrsa 4096 | save -f $private_key_file
    chmod 400 $private_key_file
    openssl rsa -in $private_key_file -out $public_key_file -pubout err>| ignore

    info $CFG "Generating domain private key ..."

    openssl genrsa 4096 | save -f $domain_key_file
    chmod 400 $domain_key_file

    info $CFG $"New private key: ($private_key_file)"
    info $CFG $"New public key: ($public_key_file)"
    info $CFG $"New domain key: ($domain_key_file)"
}

def create-order [
    CFG: record
    CTX: record
] {
    info $CFG "Creating order ..."
  
    mut identifiers = []

    for domain in $CTX.domains {
        $identifiers = (
            $identifiers
            | append {
                type: 'dns'
                value: $domain
            }
        )
    }

    let uri = $CTX.acme.uri.newOrder;
   

    let local_ctx = $CTX | merge {
        jwk: { kid: $CTX.account_id }
        private_key_file: $CTX.private_key_file
    }

    let res = api-request $CFG $local_ctx $uri { identifiers: $identifiers}
   
    ## TODO: handle error return
    if ($res | to-json-raw | str contains 'urn:ietf:params:acme:error') {
        err $CFG "API error"
        err $CFG $"Response status: ($res.status)"
        err $CFG $"Response body: ($res.body)"
    }

    let authorizations = $res.body.authorizations
    let identifiers = $res.body.identifiers

    if ($authorizations | length) != ($identifiers | length) {
        err $CFG $"authorizations and identifiers length are not equal"
        err $CFG $"check logs for further inspection"
    }

    info $CFG "Order placed"

    return {
        order_uri: (extract-location-header $res)
        status: $res.body.status
        expires: $res.body.expires
        authorizations: $res.body.authorizations
        identifiers: $res.body.identifiers
        finalize: $res.body.finalize
    }
}

def get-order-status [
    CFG: record
    CTX: record
    order: record
    force_no_cache: bool = false
] {
    info $CFG "Getting order status ..."
     
    let uri = $order.order_uri;
    let local_ctx = $CTX | merge {
        jwk: { kid: $CTX.account_id }
        private_key_file: $CTX.private_key_file
    }

    let res = api-request $CFG $local_ctx $uri ""
    # let not_pending = ($res.body.status != "pending")

    ## TODO: handle error return
    if ($res | to-json-raw | str contains 'urn:ietf:params:acme:error') {
        err $CFG "API error"
        err $CFG $"Response status: ($res.status)"
        err $CFG $"Response body: ($res.body)"
    }

    info $CFG "Order status queried successfully"

    return {
        order_uri: $uri
        status: $res.body.status
        expires: $res.body.expires
        authorizations: $res.body.authorizations
        identifiers: $res.body.identifiers
        finalize: $res.body.finalize
        certificate: ($res.body | default "" certificate | get certificate)
    }
}

def get-challange-token [
    CFG: record
    CTX: record
    order: record
] {
    info $CFG "Getting challanges tokens"
     
    let authorizations = $order.authorizations | wrap authorizations
    let domain_authz = (
        $order.identifiers | select value
        | merge $authorizations | rename domain authorization
    )

    let local_ctx = $CTX | merge {
        jwk: { kid: $CTX.account_id }
        private_key_file: $CTX.private_key_file
    }
    
    mut challenges = []

    for row_domain_authz in $domain_authz {
        info $CFG $"for domain: ($row_domain_authz.domain)"
        info $CFG $"authorization url: ($row_domain_authz.authorization)"

        let uri = $row_domain_authz.authorization

        let res = api-request $CFG $local_ctx $uri ""

        ## TODO: handle error return
        if ($res | to-json-raw | str contains 'urn:ietf:params:acme:error') {
            err $CFG "API error"
            err $CFG $"Response status: ($res.status)"
            err $CFG $"Response body: ($res.body)"
        }

        $challenges = ($challenges | append $res)
    } 

    ## =======================================================
    debug $CFG $"Cleaning challenges"
    let cleaned = clean-challenges $CFG $CTX $challenges
    $cleaned
}

def clean-challenges [CFG: record, $CTX:record challenges: list] {
    let jwk_thumbprint = $CTX.jwk_thumbprint
    mut cleaned = []
    for $challange in $challenges {
        let wildcard = ($challange.body |  default false wildcard | get wildcard )
        let domain = if $wildcard {
            $"*.($challange.body.identifier.value)"
        } else {
            $challange.body.identifier.value
        }

        $cleaned ++= ($challange.body.challenges | each { |v| 
            let keyauths = $"($v.token).($jwk_thumbprint)"
            let sha_256_keyauth = (
                $keyauths
                    | openssl dgst -sha256 -hex
                    | split words | last
                    | decode hex
                    | encode-base64-nopad-url 
            )

            {
                full_domain: $domain
                domain: $challange.body.identifier.value
                wildcard: $wildcard,
                keyauths: $keyauths
                sha_256_keyauth: $sha_256_keyauth
                domain_status: $challange.body.status
                expires: $challange.body.expires
                ...$v
            }
        })
    }

    $cleaned
}


def prove-possession [
    CFG: record
    CTX: record
    cleaned_challenges: list
] {
    info $CFG "Proving Possession of domain"

    let http_01_challenge = (
        $cleaned_challenges
            | where { $in.wildcard == false }
            | flatten
            | where { $in.type == 'http-01'}
        )

    let dns_01_challenge = (
        $cleaned_challenges
            | where { $in.wildcard == true }
            | flatten
            | where { $in.type == 'dns-01'}
    )

    let web_root_dir = $"($CFG.RUN_DIR)/.well-known/acme-challenge"

    if ($web_root_dir | path exists ) {
        rm -rf $web_root_dir
    }
    mkdir $web_root_dir

    for challange in $http_01_challenge {
        try { rm -rf $"($web_root_dir)/($challange.token)" }
        $challange.keyauths | save -f $"($web_root_dir)/($challange.token)"
    }

    if ($http_01_challenge | is-not-empty) {

        ## http_01 challenges gen command
        let cmds = (
            $http_01_challenge
            | each { |v| $"scp '($web_root_dir)/($v.token)' /path/to/server/webroot"}
        )


        ## TODO: Add documentation link
        print $"
═══════════════════════════════════════════════════════════════════════════════

┌──────────────────────────────────────────────────────────────────────────────┐
│ For http-01 challenges                                                       │
└──────────────────────────────────────────────────────────────────────────────┘

Run following command below:

($cmds | str join "\n")

OR

copy all the files inside '($web_root_dir)' directory to webroot of your project

"
    }



    if ($dns_01_challenge | is-not-empty) {
        let dns_txts = $dns_01_challenge | each { |v|
            let domain = $v.domain
            let sha_256_keyauth = (
                $v.keyauths
                    | openssl dgst -sha256 -hex
                    | split words | last
                    | decode hex
                    | encode-base64-nopad-url 
            )

            $'_acme-challenge.($domain). 300 IN TXT "($sha_256_keyauth)"'
        }

        ## TODO: Add documentation link
        print $"
┌──────────────────────────────────────────────────────────────────────────────┐
│ For dns-01 challenges                                                        │
└──────────────────────────────────────────────────────────────────────────────┘

Save give data in your dns provider dashboard

($dns_txts  | str join "\n")


You can check websites like https://dnschecker.org to check if DNS propogation

═══════════════════════════════════════════════════════════════════════════════
"
    }

    let _ = input "When done press enter..."

    let all_challenges = ($http_01_challenge | append $dns_01_challenge)

    loop {
        let local_status = local-check-challenges $CFG $CTX $all_challenges

        let is_local_success = (
            $local_status
            | where { $in.status == "failed" }
            | length
        ) == 0

        if not $is_local_success {
            err $CFG "Due to previous warning intervention requried" 
            let choice = ([c r q] | input "Press [c] to continue, [r] to retry (default), [q] to exit: " --default "r")
            match $choice {
                'c' => {
                    # TODO: check if existing files are correct format
                    warn $CFG "Ignoring error and continuing ..."
                    break
                },
                'r' => {
                    info $CFG "Retrying ..."
                    continue 
                },
                'q' => {
                    info $CFG "Exiting..."
                    exit 0
                },
                _ => {
                    err $CFG "Invalid option! Retrying ..."
                    continue 
                },
            }
        } else {
            info $CFG "Local challenges succeed" 
            break
        }
    
    }

    let sure = (
        input --default "n" "Do you really want to respond to challenges (y/N) " | str trim | str downcase
    )

    if not ($sure == "Y" or $sure == "y") {
        info $CFG "Exiting..."
        exit 0
    }

    info $CFG "Responding to challenges ..."

    let local_ctx = $CTX | merge {
        jwk: { kid: $CTX.account_id }
        private_key_file: $CTX.private_key_file
    }
    
    mut responses = []

    for challange in $all_challenges {
        let uri = $challange.url
        debug $CFG $"For domain: ($challange.full_domain)"
        debug $CFG $"Responding to challenge uri: ($uri)"

        let res = api-request $CFG $local_ctx $uri {}
        ## TODO: handle error return
        if ($res | to-json-raw | str contains 'urn:ietf:params:acme:error') {
            err $CFG "API error"
            err $CFG $"Response status: ($res.status)"
            err $CFG $"Response body: ($res.body)"
        }
        $responses = ($responses | append $res)
    }

    # let all_valid = ($responses | all { $in.status == "valid" })

    info $CFG "Done proving possession"
    $responses
}

def local-check-challenges [
    CFG: record
    CTX: record
    challenges: list
] {

    info $CFG "Checking token status ..."

    mut responses = []

    let http_01 = ($challenges | where { $in.type == "http-01" })
    let dns_01 = ($challenges | where { $in.type == "dns-01" })

    for challenge in $http_01 {
        let domain = $challenge.domain
        let full_domain = $challenge.full_domain
        let token = $challenge.token
        let keyauths = $challenge.keyauths
        let uri = $"http://($domain)/.well-known/acme-challenge/($token)"
        let res = (
            http get
              --full
              --allow-errors
              --headers $CFG.HEADERS
              --max-time $CFG.MAX_TIMEOUT_DURATION
              $uri
        )
        let body = ($res | default "" body | get body)
        if $body == $keyauths {
            info $CFG $"success: token for domain: ($full_domain) is set"
            $responses ++= [
                {
                    type: $challenge.type
                    full_domain: $full_domain
                    status: "success"
                    reason: ""
                }
            ]
        } else {
            let $message = $"failed: token NOT found for domain: ($challenge.full_domain)"
            warn $CFG $message { token: $token}
            $responses ++= [
                {
                    type: $challenge.type
                    full_domain: $full_domain
                    status: "failed"
                    reason: $message
                }
            ]
        }
    }
    let is_dig_installed = ((which dig | length ) > 0)

    for challenge in $dns_01 {
        let domain = $challenge.domain
        let full_domain = $challenge.full_domain
        let token = $challenge.token
        let keyauths = $challenge.keyauths
        let sha_256_keyauth = $challenge.sha_256_keyauth

        if not $is_dig_installed {
            let message = "Dig not installed, Cannot check wildcard domains"
            warn $CFG $message
            $responses ++= [
                {
                    type: $challenge.type
                    full_domain: $full_domain
                    status: "failed"
                    reason: $message
                }
            ]
            continue
        }

        let dig_res = (dig TXT $"_acme-challenge.($domain)" +short)
        ## eg. response: _acme-challenge.www.example.com. 300 IN TXT "..."
        let res_sha_256 = ($dig_res | str replace --all '"' "")

        if $sha_256_keyauth != $res_sha_256 {
            let message = "failed: Invlid SHA256 token"
            warn $CFG $message { found: $res_sha_256, expected: $sha_256_keyauth }
            $responses ++= [
                {
                    type: $challenge.type
                    full_domain: $full_domain
                    status: "failed"
                    reason: $message
                }
            ]
        } else {
            info $CFG $"success: token for domain: ($full_domain) is set"
            $responses ++= [
                {
                    type: $challenge.type
                    full_domain: $full_domain
                    status: "success"
                    reason: ""
                }
            ]
        }
    }

    $responses
}

def poll-challenge-response [
    CFG: record
    CTX: record
    order: record
] {
    info $CFG "Waiting for validation ..."

    mut status = ""

    for attempt in [1 2 3 4 5] {
        let sleep_duration = ($"(4 * $attempt)sec" | into duration) 
        info $CFG $"\(Re\)trying after ($sleep_duration)"
        sleep $sleep_duration
        let order_status = get-order-status $CFG $CTX $order

        $status = $order_status.status

        if $status != "pending" {
            break
        }
        info $CFG $"attempt ($attempt); status:($status)"
    }
    
    match $status {
        "ready" => {
            info $CFG "Validation successful."
            $status
        }
        "invalid" => {
            err $CFG "The server unsuccessfully validated your authorization challenge(s). Cannot continue."
            err $CFG "Check logs for more information."
            exit 1
        }
        _ => {
            err $CFG $"Timeout. Certificate order status is still '($status)' instead of 'ready'. Something went wrong validating the authorization challenge\(s\). Cannot continue."
        		exit 1
        }
        
    }
}

def generate-csr [
    CFG: record
    CTX: record
] {

    info $CFG "Creating CSR ..."
    let domain_key = ($CTX.domain_key_file)

    # subjectAltName = DNS:yoursite.com, DNS:www.yoursite.com
    let subject_alt_name = (
        $CTX.domains
        | each { |domain|
            $"DNS:($domain)"
        }
    ) | do { $"subjectAltName = ($in | str join ', ')" }


    ## openssl >= 1.1.1 required (no openssl config file needed)
    let csr = (openssl req -new -sha256 -key $domain_key -subj "/" -addext $subject_alt_name)

    # save csr
    let csf_file = $"($CFG.RUN_DIR)/domain.csr"
    $csr | save -f $csf_file

    info $CFG $"Done creating ($csf_file)"

    return $csr
}

def finalizing-order [
    CFG: record
    CTX: record
    order: record
] {
    let csf_file = $"($CFG.RUN_DIR)/domain.csr"

    let csr_encoded = (
        openssl req -in $csf_file -inform PEM -outform DER
        | encode-base64-nopad-url
    )

    let uri = $order.finalize;
    let local_ctx = $CTX | merge {
        jwk: { kid: $CTX.account_id }
        private_key_file: $CTX.private_key_file
    }

    let res = api-request $CFG $local_ctx $uri { csr: $csr_encoded}

    ## TODO: handle error return
    if ($res | to-json-raw | str contains 'urn:ietf:params:acme:error') {
        err $CFG "API error"
        err $CFG $"Response status: ($res.status)"
        err $CFG $"Response body: ($res.body)"
    }

    mut status = ""

    for attempt in [1 2 3] {
        let retry_after = try {
           (extract-header-value $res "retry-after" | into int)
        }
    
        let retry_after = try {
            if ($retry_after == null) {
                let n = (extract-header-value $res "retry-after" | date to-timezone $"(date now | format date '%z')")
                let diff = ((date now) - $n)
                let diff = ($diff | format duration sec | split words | first | into int)
                $diff
            } else {
                $retry_after
            }
        } catch {
            4 # 4 seconds if cannot extract retry-after
        }

        let sleep_duration = ($"($retry_after + 1)sec" | into duration) 
        info $CFG $"\(Re\)trying after ($sleep_duration)"
        sleep $sleep_duration

        let order_status = get-order-status $CFG $CTX $order
        $status = $order_status.status
        info $CFG $"attempt ($attempt); status:($status)"

        if $status == "processing" {
            continue 
        } else {
            break
        }
    }

    match $status {
        "valid" => { info $CFG "Order valid"}
        "processing" => {
            err $CFG "Error in finalizing order"
            err $CFG "Order still processing after 3 attempts"
        }
        _ => {
            err $CFG $"Certificate order status is '($status)' instead of \"valid\". Something went wrong issuing the certificate. Cannot continue."
        		exit 1
        }
    }
}

def download-certificate [
    CFG: record
    CTX: record
    order: record
] {
    let certificate_url = $order.certificate

    debug $CFG $"certificate_url: ($certificate_url)"

    info $CFG "Downloading certificate ..."

    let uri = $certificate_url;
    let local_ctx = $CTX | merge {
        jwk: { kid: $CTX.account_id }
        private_key_file: $CTX.private_key_file
    }

    let res = api-request $CFG $local_ctx $uri ""
    
    # Response contains the server and intermediate certificate(s).
    # Store all in one chained file. They are in the right order already.
    let domain_fullchain = $"($CFG.RUN_DIR)/fullchain.pem"
    let domain_chain = $"($CFG.RUN_DIR)/chain.pem"

    let fullchain = parse-certificate $res.body
    let chain = $fullchain | last

    $fullchain | str join "\n\n"| save -f $domain_fullchain
    $chain | save -f $domain_chain
    info $CFG $"Success! Certificate fullchain saved to: ($domain_fullchain)"
    info $CFG $"Success! Certificate chain saved to: ($domain_chain)"

    $res
}

def parse-certificate [cert: string] {
    let cert_chain = ($cert
    | lines
    | where { |v|
        ($v | str length) != 0
    }
    | reduce --fold [[]] { |it, acc|
        let last = ($acc | last)
        let len = ($acc | length)

        let latest = ($last | append $it)

        if ($it | str starts-with "-----END" ) {
            [...($acc | take ($len - 1)) $latest []]
        } else {
            [...($acc | take ($len - 1)) $latest]
        }
    }
    | where { |v|
        ($v | length) != 0
    }
    | each { |v|
        $v | str join "\n"
    })

    return $cert_chain    
}

export def main [
    --staging
    --agree-tos
    --verbose
    --write-log
    --show-extra-log
    --use-exixting-account
    --email (-e): string = ""
    --domain (-d): string = "" 
    --dir-uri: string = ""
    --debug-save-response
    ...rest: any
] {
    mut CFG = $DEFAULT_CFG | merge {
        STAGING: $staging
        AGREE_TOS: $agree_tos
        LOG_LEVEL: (if $verbose { 0 } else { $DEFAULT_CFG.LOG_LEVEL })
        WRITE_LOG: $write_log
        SHOW_EXTRA_LOG: $show_extra_log
        USE_EXISTING_ACCOUNT: $use_exixting_account 
        DIR_URI: $dir_uri
        DEBUG_SAVE_RESPONSE: $debug_save_response
    }

    ## Init dirs
    ^mkdir -p $CFG.LOG_DIR
    ^mkdir -p $CFG.RUN_DIR

    ## TODO: check if domains is empty list
    let domains = (
        $domain | str trim | split row --regex '[,\s]+'
        | each { $in | str trim }
        | where { $in | is-not-empty }
    )
    
    let emails = (
        $email | str trim | split row --regex '[,\s]+'
        | each { $in | str trim }
        | where { $in | is-not-empty }
    ) 

    let CTX = {
        domains: $domains                
        emails: $emails                
    }    

    ## TODO: term of service agreement

    let directory = get-acme-directory $CFG
    let acme_uris = get-acme-uri $directory
    
    let CTX = $CTX | merge {
        acme: {
            uri: $acme_uris
        }
    }

    let account_info = get-account-info $CFG $CTX 

    let CTX = $CTX | merge {
        account_id: $account_info.account_id
        private_key_file: $account_info.private_key_file
        public_key_file: $account_info.public_key_file
        domain_key_file: $account_info.domain_key_file
        jwk_thumbprint: $account_info.jwk_thumbprint
    }

    debug $CFG $"account_id: ($account_info.account_id)"
    debug $CFG $"jwk_thumbprint: ($account_info.jwk_thumbprint)"

    let order = create-order $CFG $CTX

    let order_status = get-order-status $CFG $CTX $order

    let cleaned_challenges = get-challange-token $CFG $CTX $order

    let responses = prove-possession $CFG $CTX $cleaned_challenges

    poll-challenge-response $CFG $CTX $order
     
    let csr = generate-csr $CFG $CTX

    finalizing-order $CFG $CTX $order

    let order_status = get-order-status $CFG $CTX $order
    download-certificate $CFG $CTX $order_status
    # print $"($order_status | to json)"

    null
}
## https://github.com/diafygi/gethttpsforfree
## https://github.com/letsencrypt/pebble
