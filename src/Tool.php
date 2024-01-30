<?php

namespace Jrglasgow\C2paTool;

use Jrglasgow\C2paTool\Exceptions\CertificateValidationException;
use phpseclib3\Crypt\PublicKeyLoader;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;
use stdClass;
use Symfony\Component\Process\Process;
use Jrglasgow\C2paTool\Exceptions\RuntimeException;

class Tool implements LoggerAwareInterface {

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
   * @var \Psr\Log\LoggerInterface
   */
  protected LoggerInterface $logger;

  /**
   * The location fo the c2patool binary
   * @var string|false
   */
  protected string|false $binary;

  protected string $binaryVersion;

  public function __construct(LoggerInterface $logger) {
    $this->setLogger($logger);
    $this->searchBinary();
  }

  public function setLogger(LoggerInterface $logger): void {
    $this->logger = $logger;
  }

  /**
   * Search the system to see if we can find the c2patool binary
   *
   * @return false|string
   */
  protected function searchBinary() {
    $search_paths = [
      '/usr/local/bin',
      '/usr/bin',
      '/usr/sbin',
    ];
    foreach ($search_paths AS $path) {
      // check to see if c2patool exists in the path
      $file_path = $path . '/c2patool';
      if (file_exists($file_path) && is_executable($file_path)) {
        $this->binary = $file_path;
        $this->setBinaryVersion();
      }
    }
    return FALSE;
  }

  /**
   * Set the binary path in $this->binary.
   *
   * @return void
   */
  public function setBinary($file_path) {
    $this->binary = $file_path;
    $this->setBinaryVersion();
  }

  /**
   * get $this->binary
   *
   * @return false|string
   */
  public function getBinary() {
    return $this->binary;
  }

  /**
   * get $this->>binaryVersion
   *
   * @return mixed
   */
  public function getBinaryVersion() {
    return $this->binaryVersion;
  }


  private function setBinaryVersion() {
    $timeout = 60;
    if (isset($this->binary) && file_exists($this->binary) && is_executable($this->binary)) {
      $output = $this->executeCommand('--version');
      $version = trim(str_replace('c2patool', '', $output));
      $this->binaryVersion = $version;
      return $output;
    }
    return FALSE;
  }

  private function executeCommand($command, $timeout = 60) {
    $command = $this->binary . ' ' . $command;
    $process = Process::fromShellCommandline($command);
    $process->setTimeout($timeout);
    $this->logger->info(sprintf('C2paTool\Tool executes command %s', $process->getCommandLine()));
    $process->run();

    if ( ! $process->isSuccessful()) {
      throw new RuntimeException(sprintf('Command %s failed : %s, exitcode %s', $command, $process->getErrorOutput(), $process->getExitCode()));
    }

    $output = $process->getOutput();

    unset($process);

    return $output;
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
  public function validateCert($cert_path, $key_path, $cert_file = new stdClass()) {
    $request_time = $_SERVER['REQUEST_TIME'] ?? time();
    // if any of tests fail, tthe certificate fails with an exception

    // here we go through the steps to validate the certificate
    $x509 = new \phpseclib3\File\X509();
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

    if (!$this->algorithmToUse($cert_file)) {
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

  protected function algorithmToUse($cert_file) {
    $signatureAlgorithms = self::SIGNATURE_ALGORITHMS;
    $certAlgorithm = $cert_file->decodedCert['signatureAlgorithm']['algorithm'];
    $algo = $signatureAlgorithms[$certAlgorithm];
    return $algo ?? FALSE;
  }

}
