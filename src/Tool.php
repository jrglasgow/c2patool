<?php

namespace Jrglasgow\C2paTool;

use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;
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
  protected string|false $binary = '';

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
    // load th path
    $path = getenv('PATH');
    $search_paths = explode(':', $path);
    // search the path
    foreach ($search_paths AS $path) {
      // check to see if c2patool exists in the path
      $file_path = $path . '/c2patool';
      if (file_exists($file_path) && is_executable($file_path)) {
        $this->binary = $file_path;
        $this->setBinaryVersion();
        if ($this->getBinaryVersion()) {
          // a version was returned... since it is the first item in the $PATH
          // we will stop looking
          return $this->getBinaryVersion();
        }
      }
    }
    return FALSE;
  }

  /**
   * Set the executable path in $this->binary. If a version cannot be retrieved
   * (file not found or not executable) then FALSE is returned and no permanent
   * change is made.
   *
   * @return false|string
   */
  public function setBinary($file_path): bool|string {
    $old_binary = $this->binary;
    $this->binary = $file_path;
    if ($this->setBinaryVersion()) {
      return $this->setBinaryVersion();
    }
    $this->binary = $old_binary;
    return FALSE;
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
    $output = $this->executeCommand('--version');
    $version = trim(str_replace('c2patool', '', $output));
    $this->binaryVersion = $version;
    return $output ?? FALSE;
  }

  /**
   * Executes a command with the binary executable.
   *
   * @param $command
   * @param $timeout
   *
   * @return string
   */
  public function executeCommand($command, $timeout = 60): string {
    $command = $this->binary . ' ' . $command;
    if (isset($this->binary) && file_exists($this->binary) && is_executable($this->binary)) {
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
    else {
      $this->logger->error('Command `@command` could not be run as there was a problem with the executable. <pre>@checks</pre>', [
        '@command' => $command = $this->binary . ' ' . $command,
        '@checks' => print_r([
          'isset(\''. $this->binary . '\')' => isset($this->binary),
          'file_exists(\''. $this->binary . '\')' => file_exists($this->binary),
          'is_executable(\''. $this->binary . '\')' => is_executable($this->binary),
        ], TRUE),
      ]);
    }
  }

}
