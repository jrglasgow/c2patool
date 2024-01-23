<?php

namespace Jrglasgow\C2paWrapper;

use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;

class Tool implements LoggerAwareInterface {

  /**
   * @var \Psr\Log\LoggerInterface
   */
  protected LoggerInterface $logger;

  public function setLogger(LoggerInterface $logger): void {
    $this->logger = $logger;
  }

}
