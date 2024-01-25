<?php

namespace Jrglasgow\C2paWrapper;

use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;

class Tool implements LoggerAwareInterface {

  /**
   * The signature types allowed - see https://opensource.contentauthenticity.org/docs/manifest/signing-manifests#signature-types
   */
  const SIGNATURE_ALGORITHMS = [
    'ecdsa-with-SHA256',
    'ecdsa-with-SHA384',
    'ecdsa-with-SHA512',
    'sha256WithRSAEncryption',
    'sha384WithRSAEncryption',
    'sha512WithRSAEncryption',
    'prime256v1',
    'secp384r1',
    'secp521r1',
    'id-Ed25519',
  ];

  /**
   * @var \Psr\Log\LoggerInterface
   */
  protected LoggerInterface $logger;

  public function setLogger(LoggerInterface $logger): void {
    $this->logger = $logger;
  }

}
