# C2PATool
# Introduction
This is a PHP wrapper for the [c2patool command line binary](https://github.com/contentauth/c2patool) provided by the [Content Authenticity Initiative](https://contentauthenticity.org/). The intent is to make it easier to add signed manifests to media assets as well as reading/validating those signed manifests.

# Usage

## The Tool class
The tool class is the actual wrapper would the c2patool excutable. This Class will pass commands off to the exceutable and return any output.

### Creating the Tool
```
$tool = new \Jrglasgow\C2paTool\Tool(Psr\Log\LoggerInterface $logger);
```
By default the Tool constructor will search the `$PATH` for the c2patool executable. If it can be found it will be used...if you wish for a different version of the utility to be used you can specify
```
$tool->setBinary('/path/to/bin/c2patool');
```

## The Signer class
The Signer class will handle all things certificate and will sign the media asset manifests.

### Validating the cert can be used for Content Authenticity
You can validate that the certificate can be used for Content Credential signing by passing the certificate/key locations into the Signer::validateCert() method. If you pass in a stdClass object information about the certificate will be placed in the object for later use. Certificate MUST follow the specification in the [Content Authenticity Initiative documentation for Signing Manifests](https://opensource.contentauthenticity.org/docs/manifest/signing-manifests/#certificates).

```
$is_valid = \Jrglasgow\c2patool\Signer::validateCert($cert_file_path, $key_file_path, $cert_file);
```
If `$cert_file_path = 'ENVIRONMENT_VARIABLE';` and `$key_file_path = ''ENVIRONMENT_VARIABLE';` then instead of looking for the key and cert files on the file shystem the environment variables C2PA_PRIVATE_KEY and C2PA_SIGN_CERT variables will be used instead as [allowed in the c2patool documentation](https://github.com/contentauth/c2patool/blob/main/docs/x_509.md).


### Creating a new Signer
As with certificate validation if `$cert_file_path = 'ENVIRONMENT_VARIABLE';` and `$key_file_path = ''ENVIRONMENT_VARIABLE';` then instead of looking for the key and cert files on the file shystem the environment variables C2PA_PRIVATE_KEY and C2PA_SIGN_CERT variables will be used instead as [allowed in the c2patool documentation](https://github.com/contentauth/c2patool/blob/main/docs/x_509.md).
```
$signer = new Jrglasgow\C2paToolSigner($tool, $cert_file_path, $key_file_path);
```

### Signing and embedding a manifest
#### Creating a Manifest
Create your manifest as a JSON string or an Array using the [examples](https://opensource.contentauthenticity.org/docs/manifest/manifest-examples/) as a reference. The manifest will be modified and converted to a string afterwards.. The signature algorithm (alg), Private Key (private_key) and Sign Certificate (sign_cert) need not be included as they will be replaced with the information from the certificate when creating the Signer object. If the Claim Generator (claim_generator) is left empty one will be inserted automatically. Likewise if the Time Authority (ta_url) is left empty one will be inserted as well.

### Invoke the sign method
```
$success = $signer->sign($source_file, $destination_file, $manifest);
```
