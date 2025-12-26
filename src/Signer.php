<?php

namespace Jrglasgow\C2paTool;

use Jrglasgow\C2paTool\Exceptions\CertificateValidationException;
use phpseclib3\Crypt\EC\Formats\Keys\Common as CommonKeys;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\File\X509;
use stdClass;

/**
 * Will sign and embed a manifest.
 */
class Signer {
  use CommonKeys;
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
    'image/jpg',
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
    'secp256r1' => 'ES256',
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
   * Path to an executable that will sign the claim bytes
   *
   * @var string
   */
  protected string $remoteSignerPath = '';

  /**
   * how much space to reserve in the manifest for the signature
   */
  protected int $reserveSize = 20458;

  /**
   * if the signature should be verified
   *
   * @var bool
   */
  protected $noSigningVerify = FALSE;

  protected $cannotSign = FALSE;

  /**
   * @param \Jrglasgow\C2paTool\Tool $tool
   * @param string $cert_file_path
   * @param string $key_file_path
   *
   * @throws \Jrglasgow\C2paTool\Exceptions\CertificateValidationException
   */
  public function __construct(Tool $tool, string $cert_file_path, string $key_file_path, \stdClass $certDetails = NULL) {
    $this->tool = $tool;


    if (empty($certDetails)) {
      // validate that the certificate matches the requirements
      $certDetails = new \stdClass();
      self::validateCert($cert_file_path, $key_file_path, $certDetails);
    }
    // if the certificate is not valid an exception will be thrown and this will
    // not execute

    $this->certFilePath = $cert_file_path;
    $this->keyFilePath = $key_file_path;
    $this->certDetails = $certDetails;
    $this->certDetails->key_uri = $key_file_path;
  }

  /**
   * Add a manifest and sign a file
   *
   * @param string $source_file The source file path
   * @param string $destination_file The output path for the resulting signed media file
   * @param string|array $manifest The manifest which can be turned into JSON (or one that is already JSON)
   * @param string $parent_file The parent file that the source was derived from
   *
   * @return true
   */
  public function sign(string $source_file, string $destination_file, string|array $manifest, string $parent_file = ''): bool {
    if ($this->cannotSign) {
      return $this->cannotSign;
    }

    $manifest_string = (string) $this->adjustManifest($manifest);

    // save the manifest is a temp file
    $manifest_file_path = tempnam(sys_get_temp_dir(), 'c2patool-manifest-' . basename($source_file));
    file_put_contents($manifest_file_path, $manifest_string);



    $command_args = [
      $source_file,// the file we are signing
      '--manifest', // the manifest is being provided on the command line
      $manifest_file_path,
    ];

    if (!empty($this->remoteSignerPath) && file_exists($this->remoteSignerPath) && is_executable($this->remoteSignerPath)) {
      // add the remote signer
      $command_args[] = '--signer-path';
      $command_args[] = $this->remoteSignerPath;
      // add the reserve-size
      $command_args[] = '--reserve-size';
      $command_args[] = $this->reserveSize;

      if ($this->noSigningVerify) {
        $command_args[] = '--no_signing_verify';
      }
    }

    $replace_original = FALSE;
    if ($source_file == $destination_file) {
      $replace_original = TRUE;
      // we are overwriting the source
      // $command_args[] = '-f';

      // There is a problem with c2patool not working with the -f or --force flag
      // in >9.9.12
      // instead we will change the name of the destination file by adding the
      // microtime to the destination file name
      $destination_file_modifier = \microtime(TRUE);
      $path_info = \pathinfo($destination_file);
      $original_destination = $destination_file;
      $temp_destination = $path_info['dirname'] . '/' . $path_info['filename'] . '-temp-' . $destination_file_modifier . '.' . $path_info['extension'];
      $destination_file = $temp_destination;
    }

    if (!empty($parent_file) && file_exists($parent_file)) {
      $command_args[] = '--parent';
      $command_args[] = $parent_file;
    }

    $command_args[] = '-o ';
    $command_args[] = $destination_file;
    $command = implode(' ', $command_args);
    $result = $this->tool->executeCommand($command, 60);
    if ($result && $replace_original) {
      // since replacing the original was requested copy the new destination file
      // over the original file
      rename($destination_file, $source_file);
    }
    // remove the temp manifest file
    unlink($manifest_file_path);
    return $result;
  }

  /**
   * Get the tool object.
   *
   * @return \Jrglasgow\C2paTool\Tool
   */
  public function getTool() {
    return $this->tool;
  }

  /**
   * Make sure the keys, signature algorithm, are set according to the
   * configuration of the Signer. Convert the manifest to a JSON string.
   *
   * @param $manifest
   *
   * @return false|string
   */
  protected function adjustManifest(string|array|stdClass $manifest): bool|string {
    if (is_string($manifest)) {
      $manifest = json_decode($manifest);
    }
    else if (is_array($manifest)) {
      // normalize the manifest (really it ends up being a stdClass if it was
      // properly formatted)
      $manifest = json_decode(json_encode($manifest));
    }


    // set the signature algorithm
    $manifest->alg = $this->recommendedSignatureType();
    if (empty($manifest->alg)) {
      // we don't have an appropriate signature algorithm, there is no point
      // continuing, we might as well fail.
      $this->cannotSign = 'Cannot sign manifest, could not find recommended algorithm for ' . $this->getSignatureAlgorithm();
    }

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
    if ($this->certFilePath == 'ENVIRONMENT_VARIABLE') {
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
      $manifest->claim_generator = __CLASS__;
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
    if (array_search(strtolower($mime_type), self::SUPPORT_MIME_TYPES)) {
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
    if (array_search(strtolower($extension), self::SUPPORT_FILE_EXTENSIONS)) {
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
    $publicKeyInfo = $this->certDetails->decodedCert['tbsCertificate']['subjectPublicKeyInfo'];
    $algorithm = NULL;
    if (isset($publicKeyInfo['algorithm']) && isset($publicKeyInfo['algorithm']['algorithm']) && !empty($publicKeyInfo['algorithm']['algorithm'])) {
      $algorithm = $publicKeyInfo['algorithm']['algorithm'];
    }
    switch ($algorithm) {
      case 'id-ecPublicKey':
        if (isset($publicKeyInfo['algorithm']['parameters']['objectIdentifier'])) {
          return $publicKeyInfo['algorithm']['parameters']['objectIdentifier'];
        }
        break;
    }
    return $this->certDetails->decodedCert['signatureAlgorithm']['algorithm'];
  }

  /**
   * get the recommended signature type based on the signature algorithm of the
   * certificate - see https://opensource.contentauthenticity.org/docs/manifest/signing-manifests/#signature-types
   *s
   * @return string
   */
  protected function recommendedSignatureType() {
    self::initialize_static_variables();
    $algorithm = $this->getSignatureAlgorithm();
    $signatureAlgorithms = self::SIGNATURE_ALGORITHMS;
    if (isset($signatureAlgorithms[$algorithm])) {
      // the algorithm matches, return the recommended Signature Type
      return strtolower($signatureAlgorithms[$algorithm]);
    }
    else if ($algorithm = array_search($algorithm, self::$curveOIDs)) {
      // the algorithm didn't match, it could be an OID, check against that list
      return strtolower($signatureAlgorithms[$algorithm]) ?? FALSE;
    }
    return FALSE;
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
    $cert_file->invalid_reasons = [];
    $cert_contents = '';
    switch ($cert_path) {
      case 'ENVIRONMENT_VARIABLE':
        $cert_contents = getenv('C2PA_SIGN_CERT');
        $key_contents = getenv('C2PA_PRIVATE_KEY');
        break;
      default:
        $cert_contents = file_get_contents($cert_path);
        if (empty($key_path) || !file_exists($key_path)) {
          // though there is no key file for this certificate, hold off throwing
          // any errors until we check everything else, just set the message
          $message = 'Certificate %cert_location is not valid, corresponding key file %key_path does not exist.';
          $args = [
            '%cert_location' => $cert_file->uri,
            '%key_path' => $key_path,
          ];
          $cert_file->invalid_reasons[] = 'MISSING_KEY_FILE';
        }
        else {
          $key_contents = file_get_contents($key_path);
        }

    }
    if (empty($cert_contents)) {
      $message = 'Certificate %cert_location is not valid, file is empty.';
      $args = [
        '%cert_location' => $cert_file->uri,
      ];
      $cert_file->invalid_reasons[] = 'EMPTY_CERT_FILE';
      throw new CertificateValidationException(strtr($message, $args), 0, NULL, $message, $args);
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
      $cert_file->invalid_reasons[] = 'CERT_EXPIRED';
      throw new CertificateValidationException(strtr($message, $args), 0, NULL, $message, $args);
    }
    else if ($request_time < strtotime($cert_file->decodedCert['tbsCertificate']['validity']['notBefore']['utcTime'])) {
      $message = 'Certificate %cert_location is not valid, not until at %begins_valid.';
      $args =  [
        '%cert_location' => $cert_file->uri,
        '%begins_valid' => $cert_file->decodedCert['tbsCertificate']['validity']['notBefore']['utcTime'],
      ];
      $cert_file->invalid_reasons[] = 'CERT_NOT_YET_VALID';
      throw new CertificateValidationException(strtr($message,$args), 0, NULL, $message, $args);
    }

    // check that cert uses valid signature algorithm

    if (!self::algorithmToUse($cert_file)) {
      $message = 'Certificate %cert_location\'s signature algorithm (%signature_algorithm) is not compatible with the allowed algorithms <pre>%allowed_signature_algorithms</pre>';
      $args = [
        '%cert_location' => $cert_file->uri,
        '%signature_algorithm' => $cert_file->decodedCert['signatureAlgorithm']['algorithm'],
        '%allowed_signature_algorithms' => print_r(self::SIGNATURE_ALGORITHMS, TRUE),
      ];
      $cert_file->invalid_reasons[] = 'CERT_SIGNATURE_NOT_COMPATIBLE';
      throw new CertificateValidationException(strtr($message, $args), 0, NULL, $message, $args);
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
      $cert_file->invalid_reasons[] = 'CERT_NOT_X509_V3';
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
      $cert_file->invalid_reasons[] = 'CERT_DIGITAL_SIGNATURE_NOT_ENABLED';
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
      if ($extensions['id-ce-basicConstraints']['extnValue']['cA']) {
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
      $cert_file->invalid_reasons[] = 'CERT_BASIC_CONSTRAINTS_INVALID';
      throw new CertificateValidationException(strtr($message,$args), 0, NULL, $message, $args);
    }

    // TODO check for "id-kp-documentSigning" - PHPSecLibs doesn't know about it yet



    if (empty($key_contents)) {
      if (!isset($message)) {
        $message = 'Certificate %cert_location is not valid, corresponding key file %key_path is empty.';
        $args = [
          '%cert_location' => $cert_file->uri,
          '%key_path' => $key_path,
        ];
      }
      $cert_file->invalid_reasons[] = 'KEY_FILE_EMPTY';
      throw new CertificateValidationException(strtr($message, $args), 0, NULL, $message, $args);
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
      $cert_file->invalid_reasons[] = 'COULD_NOT_VALIDATE_SIGNATURE';
      throw new CertificateValidationException(strtr($message, $args),0,NULL, $message, $args);
    }

    return TRUE;
  }

  public static function algorithmToUse($cert_file) {
    $signatureAlgorithms = self::SIGNATURE_ALGORITHMS;
    $certAlgorithm = $cert_file->decodedCert['signatureAlgorithm']['algorithm'];
    $algo = $signatureAlgorithms[$certAlgorithm];
    return $algo ?? FALSE;
  }

  /**
   * getter
   *
   * @return string
   */
  public function getRemoteSignerPath() {
    return $this->remoteSignerPath;
  }

  /**
   * setter
   *
   * @param string $path
   *
   * @return void
   */
  public function setRemoteSignerPath(string $path) {
    $this->remoteSignerPath = $path;
  }

  /**
   * getter
   *
   * @return int
   */
  public function getReserveSize() {
    return $this->reserveSize;
  }

  /**
   * setter
   *
   * @param int $reserveSize
   *
   * @return void
   */
  public function setReseveSize(int $reserveSize) {
    $this->reserveSize = $reserveSize;
  }

  /**
   * getter
   *
   * @return bool
   */
  public function getNoSigningVerioy() {
    return $this->noSigningVerify;
  }

  /**
   * setter
   *
   * @param bool $setting
   *
   * @return void
   */
  public function setNoSigningVerigy(bool $setting) {
    $this->noSigningVerify = $setting;
  }

  public function getCertFilePath() {
    return $this->certFilePath;
  }

  public function setCertFilePath(string $path) {
    $this->certFilePath = $path;
  }

  public function getKeyFilePath() {
    return $this->keyFilePath;
  }

  public function setKeyFilePath(string $path) {
    $this->keyFilePath = $path;
  }

  public function getCertDetails() {
    return $this->certDetails;
  }

  public function setCertDetails(\stdClass $certDetails) {
    $this->certDetails = $certDetails;
  }

}
