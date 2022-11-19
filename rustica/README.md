# Rustica

The server portion of the Rustica project.

## Building
Depending on your needs, Rustica can be built with several different features to enable different use cases. To build them all (generally for testing), run:
`cargo build --features=all`. Below is summary of all the optional features, what they do, and how to configure them.

## amazon-kms
This compiles in support to use AmazonKMS as the backend for signing. This requires defining two key identifiers as well as AWS credentials that can access them. These keys must be asymettric, with the Sign/Verify capabilities. Encrypt/Decrypt will not work.

### Example Configuration
```toml
[signing."amazonkms"]
aws_access_key_id = "XXXXXXXXXXXXXXXXXXXX"
aws_secret_access_key = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
aws_region = "us-west-2"
user_key_id = "mrk-00000000000000000000000000000000"
user_key_signing_algorithm = "ECDSA_SHA_384"
host_key_id = "mrk-00000000000000000000000000000000"
host_key_signing_algorithm = "ECDSA_SHA_384"
```

### yubikey-support
This compiles in support to use a connected Yubikey 4/5 as the backend for signing. This requires defining two slot identifiers in the form of R followed by a number from 1 to 20 inclusive. For example R1, R9, R12, R20. These keys must be ECDSA 256/384. RSA keys are not supported at this time.

### Example Configuration
```toml
[signing."yubikey"]
user_slot = "R2"
host_slot = "R3"
```

## influx
Compiles in support to log to an InfluxDB backend. See the example configurations for more details on how to set this up.

### Example Configuration
```toml
[logging."influx"]
address = "http://some-local-influx-instance:8080"
database = "rustica"
dataset = "rustica_logs"
user = "influx_user"
password = "influx_password"
```

## splunk
Compiles in support to log to an Splunk backend. See the example configurations for more details on how to set this up.

### Example Configuration
```toml
[logging."splunk"]
token = "c46d7213-19ea-4a66-b83b-e4b06188d197"
url = "https://http-inputs-examplecompany.splunkcloud.com/services/collector"
timeout = 5
```

## local-db
Compiles in support for Rustica to handle authorization without talking to an external service. This requires a local SQLite database with all configured permissions and grants. See `rustica/migrations/2021-01-14-051956_hosts/up.sql` for a detailed explanation of how to configure this database.

### Example Configuration
```toml
[authorization."database"]
path = "examples/example.db"
```

## HomeLab
One of the best ways to get familiar with Rustica is to run it in a homelab using a Yubikey 5 as your server side signing authority. The recommended way to achieve this is to use the homelab Dockerfile and mount the PCSC socket inside the docker container.

This will give you the benefites of service resilliancy but you also do not have to run your container in privileged mode.