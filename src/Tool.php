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
   * @var \Psr\Log\LoggerInterface
   */
  protected LoggerInterface $logger;

  /**
   * The location fo the c2patool binary
   * @var string|false
   */
  protected string|false $binary;

  /**
   * The version of the binary
   *
   * @var string
   */
  protected string $binaryVersion;

  public function __construct(LoggerInterface $logger) {
    $this->setLogger($logger);
    $this->searchBinary();
  }

  /**
   * Setting the logger property
   *
   * @param \Psr\Log\LoggerInterface $logger
   *
   * @return void
   */
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

  /**
   * Query the binary version information and tore the binary version (if we
   * have binary).
   *
   * @return false|string Returns the binary version or FALSE is it cannot be
   * found.
   */
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

  /**
   * Executes a command with the binary executable.
   *
   * @param $command
   * @param $timeout
   *
   * @return string
   */
  private function executeCommand($command, $timeout = 60): string {
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

}
