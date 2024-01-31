<?php

namespace Jrglasgow\C2paTool;

use Jrglasgow\C2paTool\Exceptions\CertificateValidationException;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\File\X509;
use stdClass;

/**
 * Will sign and embed a manifest.
 */
class Signer {

  /**
   * list of supported mime types - since there isn't a one-to-one, or a
   * one-to-many relationship between SUPPORT_MIME_TYPES and
   * SUPPORT_FILE_EXTENSIONS there couldn't easily be just one array.
   */
  const SUPPORT_MIME_TYPES = [
    'video/msvideo',
    'video/avi',
    'application-msvideo',
    'image/avif',
    'application/x-c2pa-manifest-store',
    'image/x-adobe-dng',
    'image/heic',
    'image/heif',
    'image/jpeg',
    'audio/mp4',
    'audio/mpeg',
    'video/mp4',
    'application/mp4',
    'video/quicktime',
    'image/png',
    'image/svg+xml',
    'image/tiff',
    'audio/x-wav',
    'image/webp',
  ];

  /**
   * List of support file extensions - since there isn't a one-to-one, or a
   * one-to-many relationship between SUPPORT_MIME_TYPES and
   * SUPPORT_FILE_EXTENSIONS there couldn't easily be just one array.
   */
  const SUPPORT_FILE_EXTENSIONS = [
    'avi',
    'avif',
    'c2pa',
    'dng',
    'heic',
    'heif',
    'jpg',
    'jpeg',
    'm4a',
    'mp3',
    'mp4',
    'mov',
    'png',
    'svg',
    'tif',
    'tiff',
    'wav',
    'webp',
  ];

  /**
   * The signature types allowed - see https://opensource.contentauthenticity.org/docs/manifest/signing-manifests#signature-types
   *
   * The array is
   * [
   *   Certificate Signature Algorithm => Recommended signature type
   * ]
   */
  const SIGNATURE_ALGORITHMS = [
    'ecdsa-with-SHA256' => 'ES256',
    'ecdsa-with-SHA384' => 'ES384',
    'ecdsa-with-SHA512' => 'ES512',
    'sha256WithRSAEncryption' => 'PS256',
    'sha384WithRSAEncryption' => 'PS384',
    'sha512WithRSAEncryption' => 'PS512',
    'prime256v1' => 'ES256',
    'secp384r1' => 'ES384',
    'secp521r1' => 'ES512',
    'id-Ed25519' => 'Ed25519',
  ];

  /**
   * @var \Jrglasgow\C2paTool\Tool
   */
  protected Tool $tool;

  /**
   * the path t the cert file
   *
   * @var string
   */
  protected string $certFilePath;

  /**
   * The path to the key file
   *
   * @var string
   */
  protected string $keyFilePath;

  /**
   * details about the cert
   *
   * @var \stdClass
   */
  protected \stdClass $certDetails;

  /**
   * @param \Jrglasgow\C2paTool\Tool $tool
   * @param string $cert_file_path
   * @param string $key_file_path
   *
   * @throws \Jrglasgow\C2paTool\Exceptions\CertificateValidationException
   */
  public function __construct(Tool $tool, string $cert_file_path, string $key_file_path) {
    $this->tool = $tool;

    // validate that the cetificate matches the requirements
    $certDetails = new \stdClass();
    self::validateCert($cert_file_path, $key_file_path, $certDetails);
    // if the certificate is not valid an exception will be thrown and this will
    // not execute

    $this->certFilePath = $cert_file_path;
    $this->keyFilePath = $key_file_path;
    $this->certDetails = $certDetails;
    $this->certDetails->key_uri = $key_file_path;
  }

  /**
   * Sign an asset
   *
   * @param string $source_file
   * @param string $destination_file
   * @param string $manifest
   *
   * @return true
   */
  public function sign(string $source_file, string $destination_file, string|array $manifest): bool {
    $command_args = [
      $source_file,// the file we are signing
      '--config', // the manifest is being provided on the command line
      '\'' . (string) $this->adjustManifest($manifest) . '\'',
    ];

    if ($source_file == $destination_file) {
      // we are overwriting the source
      $command_args[] = '-f';
    }

    $command_args[] = '-o ';
    $command_args[] = $destination_file;
    $command = implode(' ', $command_args);
    return $this->tool->executeCommand($command, 60);
  }

  /**
   * Make sure the keys, signature algorithm, are set according to the
   * configuration of the Signer. Convert the manifest to a JSON string.
   *
   * @param $manifest
   *
   * @return false|string
   */
  protected function adjustManifest(string|array $manifest) {
    if (is_string($manifest)) {
      $manifest = json_decode($manifest);
    }

    // set the signature algorithm
    $manifest->alg = $this->recommendedSignatureType();

    // set the private key
    if ($this->keyFilePath == 'ENVIRONMENT_VARIABLE') {
      // make sure there is no key file in the manifest if we have environment variables set
      if (isset($manifest->private_key)) {
        unset($manifest->private_key);
      }
    }
    else {
      $manifest->private_key = $this->keyFilePath;
    }

    // set the certificate
    if ($this->certFilePath == 'ENVIRONMENT_VARIABLE'){
      // make sure there is no key file in the manifest if we have environment variables set
      if (isset($manifest->sign_cert)) {
        unset($manifest->sign_cert);
      }
    }
    else {
      $manifest->sign_cert = $this->certFilePath;
    }

    // set the claim generator
    if (!isset($manifest->claim_generator) || empty($manifest->claim_generator)) {
      $manifest->claim_generator = __CLASS__ . ' - https://github.com/jrglasgow/c2patool';
    }

    // set the ta_url
    if (!isset($manifest->ta_url) || empty($manifest->ta_url)) {
      $manifest->ta_url = 'http://timestamp.digicert.com';
    }

    return json_encode($manifest);
  }

  /**
   * check to see is the mime type is supported
   *
   * @param mixed $mime_type
   *
   * @return bool
   */
  public static function mimeTypeAllowed(mixed $mime_type) {
    if (array_search($mime_type, self::SUPPORT_MIME_TYPES)) {
      return TRUE;
    }
    return FALSE;
  }

  /**
   * Check to see if the file extension is supported
   *
   * @param mixed $extension
   *
   * @return bool
   */
  public static function fileExtensionAllowed(mixed $extension) {
    if (array_search($extension, self::SUPPORT_FILE_EXTENSIONS)) {
      return TRUE;
    }
    return FALSE;
  }

  /**
   * get the signature algorithm from the certificate details
   *
   * @return mixed
   */
  protected function getSignatureAlgorithm() {
    return $this->certDetails->decodedCert['signatureAlgorithm']['algorithm'];
  }

  /**
   * get the recommended signature type based on the signature algorithm of the
   * certificate - see https://opensource.contentauthenticity.org/docs/manifest/signing-manifests/#signature-types
   *s
   * @return string
   */
  protected function recommendedSignatureType() {
    $algorithm = $this->getSignatureAlgorithm();
    $signatureAlgorithms = self::SIGNATURE_ALGORITHMS;
    return strtolower($signatureAlgorithms[$algorithm]);
  }

  /**
   * Determine if a given certificate is valid for use
   *
   * @param $cert - the text from the certificate file
   * @param $cert_file - A stdClass object into which this method will put
   * information pertaining to the certificate (decoded information, etc...).
   *
   * @return bool
   */
  public static function validateCert($cert_path, $key_path, $cert_file = new stdClass()) {
    $request_time = $_SERVER['REQUEST_TIME'] ?? time();
    // if any of tests fail, tthe certificate fails with an exception

    // here we go through the steps to validate the certificate
    $x509 = new X509();
    $cert_file->uri = $cert_path;
    $cert_file->key_uri = $key_path;
    $cert_contents = '';
    switch ($cert_path) {
      case 'ENVIRONMENT_VARIABLE':
        $cert_contents = getenv('C2PA_SIGN_CERT');
        $key_contents = getenv('C2PA_PRIVATE_KEY');
        break;
      default:
        $cert_contents = file_get_contents($cert_path);
        $key_contents = file_get_contents($key_path);

    }
    $cert_file->decodedCert = $x509->loadX509($cert_contents);

    // check if the certificate is currently valid
    // see https://opensource.contentauthenticity.org/docs/manifest/signing-manifests/#certificates
    if ($request_time > strtotime($cert_file->decodedCert['tbsCertificate']['validity']['notAfter']['utcTime'])) {
      $message = 'Certificate %cert_location is not valid, it expired at %expire.';
      $args = [
        '%cert_location' => $cert_file->uri,
        '%expire' => $cert_file->decodedCert['tbsCertificate']['validity']['notAfter']['utcTime'],
      ];
      throw new CertificateValidationException(strtr($message, $args), 0, NULL, $message, $args);
    }
    else if ($request_time < strtotime($cert_file->decodedCert['tbsCertificate']['validity']['notBefore']['utcTime'])) {
      $message = 'Certificate %cert_location is not valid, not until at %begins_valid.';
      $args =  [
        '%cert_location' => $cert_file->uri,
        '%begins_valid' => $cert_file->decodedCert['tbsCertificate']['validity']['notBefore']['utcTime'],
      ];
      throw new CertificateValidationException(strtr($message,$args), 0, NULL, $message, $args);
    }

    // check that cert uses valid signature algorithm

    if (!self::algorithmToUse($cert_file)) {
      $message = 'Certificate %cert_location\'s signature algorithm (%signature_algorithm) is not compatible with the allowed algorithms <pre>%allowed_signature_algorithms</pre>';
      $args = [
        '%cert_location' => $cert_file->uri,
        '%signature_algorithm' => $cert_file->decodedCert['signatureAlgorithm']['algorithm'],
        '%allowed_signature_algorithms' => print_r(\Jrglasgow\C2paTool\Tool::SIGNATURE_ALGORITHMS, TRUE),
      ];
      throw new CertificateValidationException(strtr($message,$args), 0, NULL, $message, $args);
    }

    // Follow the Public Key Infrastructure (PKI) X.509 V3 specification.
    $version = $cert_file->decodedCert['tbsCertificate']['version'];
    $version = str_replace('v', '', $version);
    if ($version < 3) {
      $message = 'Certificate %cert_location\'s x.509 version is %version, v3 is required.';
      $args = [
        '%cert_location' => $cert_file->uri,
        '%version' => $cert_file->decodedCert['tbsCertificate']['version'],
      ];
      throw new CertificateValidationException(strtr($message,$args), 0, NULL, $message, $args);
    }

    // validate extensions
    $extensions = [];
    foreach ($cert_file->decodedCert['tbsCertificate']['extensions'] AS $extension) {
      $extensions[$extension['extnId']] = $extension;
    }

    // Have the Key Usage (KU) extension, which must be marked as critical.
    $keyUsage = FALSE;
    if (isset($extensions['id-ce-keyUsage']) && isset($extensions['id-ce-keyUsage']['critical']) && $extensions['id-ce-keyUsage']['critical']) {
      $keyUsage = TRUE;
    }

    // Asserts the DigitalSignature Bit
    $digitalSignatureEnabled = FALSE;
    foreach ($extensions['id-ce-keyUsage']['extnValue'] AS $usage) {
      if ($usage == 'digitalSignature') {
        $digitalSignatureEnabled = TRUE;
      }
    }
    if (!$digitalSignatureEnabled) {
      $message = 'Certificate %cert_location\'s x.509 is not enabled for digital Signatures.';
      $args = [
        '%cert_location' => $cert_file->uri,
      ];
      throw new CertificateValidationException(strtr($message,$args), 0, NULL, $message, $args);
    }


    // Have the Extended Key Usage (EKU) extension
    $ekuExtension = FALSE;
    if (isset($extensions['id-ce-extKeyUsage'])) {
      $ekuExtension = TRUE;
    }

    // anyExtendedKeyUsageEKU MUST not be present
    if (isset($extensions['id-ce-anyExtendedKeyUsageEKU'])) {
      $anyExtendedKeyUsageEKU = TRUE;
    }
    else {
      $anyExtendedKeyUsageEKU = FALSE;
    }

    // test for basicConstraints
    $basisConstraints = FALSE;
    $certificateAuthority = FALSE;
    if (isset($extensions['id-ce-basicConstraints'])) {
      $basisConstraints = TRUE;
      // test for Certificate Authority
      if ($cert_file->decodedCert['tbsCertificate']['extensions'][0]['extnValue']['cA']) {
        $certificateAuthority = TRUE;
      }
    }

    // If the Basic Constraints extension is absent or the certificate
    // authority (CA) Boolean is not asserted, the EKU must be non-empty.

    if (
      (
        !$basisConstraints || // If the Basic Constraints extension is absent
        !$certificateAuthority // or the certificate authority (CA) Boolean is not asserted
      ) && (
        !isset($extensions['id-ce-extKeyUsage']['extnValue']) ||
        empty($extensions['id-ce-extKeyUsage']['extnValue']) // the EKU must be non-empty
      )
    ) {
      $message = 'Certificate %location does not meet requirements """If the Basic Constraints extension (%basicConstraints) is absent or the certificate authority (CA) Boolean is not asserted (%certificateAuthority), the EKU must be non-empty (%ekuCount item(s))""".';
      $args = [
        '%cert_location' => $cert_file->uri,
        '%basicConstraints' => $basisConstraints ? 'EXISTS' : 'ABSENT',
        '%certificateAuthority' => $certificateAuthority ? 'TRUE' : 'FALSE',
        '%ekuCount' => count($extensions['id-ce-extKeyUsage']['extnValue']),
      ];
      throw new CertificateValidationException(strtr($message,$args), 0, NULL, $message, $args);
    }

    // Validate that the key will work to sign data for the certificate
    $privateKey = PublicKeyLoader::load($key_contents);
    // generate unique data to sign
    $dataToSign = $_SERVER;
    $dataToSign[] = $request_time;
    // serialize it so we have a string
    $dataToSign = serialize($dataToSign);
    // generate the signature
    $signature = $privateKey->sign($dataToSign);

    // load the public key
    $publicKey = PublicKeyLoader::load($cert_contents);
    // verify the signature
    $validKey = $publicKey->verify($dataToSign, $signature);

    if (!$validKey) {
      $message = 'The certificate (%cert_location) and key (%key_location) are not compatible. The signature created by the key (private key) could not be validated by the certificate (public key).';
      $args = [
        '%cert_location' => $cert_file->uri,
        '%key_location' => $cert_file->key_uri,
      ];
      throw new CertificateValidationException(strtr($message, $args),0,NULL, $message, $args);
    }

    // TODO check for "id-kp-documentSigning" - PHPSecLibs doesn't know about it yet


    return TRUE;
  }

  public static function algorithmToUse($cert_file) {
    $signatureAlgorithms = self::SIGNATURE_ALGORITHMS;
    $certAlgorithm = $cert_file->decodedCert['signatureAlgorithm']['algorithm'];
    $algo = $signatureAlgorithms[$certAlgorithm];
    return $algo ?? FALSE;
  }


}
