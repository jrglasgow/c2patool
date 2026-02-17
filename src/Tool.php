<?php

namespace Jrglasgow\C2paTool;

use Jrglasgow\C2paTool\Exceptions\RuntimeException;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\Process\Process;

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

  /**
   * Environment variables to be passed to c2patool executable, if you wish to
   * remove an environment variable set it in the array with a FALSE value
   *
   * @see https://symfony.com/doc/current/components/process.html#setting-environment-variables-for-processes
   *
   * @var array
   */
  protected array $environment = [];

  public function __construct(LoggerInterface $logger) {
    $this->setLogger($logger);
    $this->searchBinary();
  }

  /**
   * Set and/or get the overwriteEnvironment setting.
   *
   * @param $setting
   *
   * @return bool
   */
  public function overwriteEnvironment($setting = NULL): bool {
    if (!empty($setting)) {
      $this->overwriteEnvironment = (bool) $setting;
    }
    return $this->overwriteEnvironment;
  }

  /**
   * Set the environment variables to use in the process.
   *
   * @return void
   */
  public function setEnvironment(array $env): void {
    $this->environment = $env;
  }


  /**
   * Get the environment variables
   *
   * @return array
   */
  public function getEnvironment(): array {
    return $this->environment;
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
  protected function searchBinary(): bool|string {
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
    $this->binaryVersion = FALSE;
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
    if (empty($file_path)) {
      // check to make sure something is being sent in
      return FALSE;
    }
    $old_binary = $this->binary;
    $this->binary = $file_path;
    if ($executable_path = $this->setBinaryVersion()) {
      return $executable_path;
    }
    $this->binary = $old_binary;
    return FALSE;
  }

  /**
   * get $this->binary
   *
   * @return false|string
   */
  public function getBinary(): bool|string {
    return $this->binary;
  }

  /**
   * get $this->>binaryVersion
   *
   * @return mixed
   */
  public function getBinaryVersion(): mixed {
    return $this->binaryVersion;
  }

  /**
   * Query the binary version information and tore the binary version (if we
   * have binary).
   *
   * @return false|string Returns the binary version or FALSE is it cannot be
   * found.
   */
  private function setBinaryVersion(): bool|string {
    $timeout = 60;
    $output = $this->executeCommand(['--version'], 30, 'NOT FOUND');
    $version = trim(str_replace('c2patool', '', $output));
    $this->binaryVersion = $version;
    return $output ?? FALSE;
  }

  /**
   * Create the Process object from the command and modify the environment
   * variables, if needed.
   *
   * @param $command
   *
   * @return \Symfony\Component\Process\Process
   */
  protected function createProcess($command): Process {
    if (is_array($command)) {
      // the best option is to have the command as arguments so Process can auto
      // escape it
      $process = new Process($command);
    }
    else {
      // a string needs to be interpreted as an already formed command which has
      // already been escaped
      $process = Process::fromShellCommandline($command, null, $this->environment);
    }

    return $process;
  }

  /**
   * Executes a command with the binary executable.
   *
   * @param $command
   * @param int $timeout
   * @param string $default the output to return if the excuted process didn't
   *                        return any output.
   *
   * @return string
   */
  public function executeCommand($command, $timeout = 60, $default = 'COULD NOT EXECUTE'): string {
    // test to make sure the binary exists and is executable
    if (is_string($command)) {
      trigger_error(
        'Passing $command as a string is deprecated, user an array of arguments',
        E_USER_DEPRECATED
      );
      $command = $this->binary . ' ' . $command;
    }
    else if (is_array($command)) {
      array_unshift($command, $this->binary);
    }
    if (isset($this->binary) && file_exists($this->binary) && is_executable($this->binary)) {
      $process = $this->createProcess($command);
      $process->setTimeout($timeout);
      $commandline = $process->getCommandLine();
      error_log($commandline);
      $this->logger->info(sprintf('C2paTool\Tool executes command %s', $process->getCommandLine()));
      $process->run(NULL, ['TEST_ENV'=>'this is only a test - still']);

      if ( ! $process->isSuccessful()) {
        throw new RuntimeException(sprintf('Command failed: %s, exitcode %s - ', $process->getErrorOutput(), $process->getExitCode(), $command));
      }

      $output = $process->getOutput();
      $errors = $process->getErrorOutput();
      $exit_code = $process->getExitCode();
      $exit_code_text = $process->getExitCodeText();

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
    // couldn't run the command so the default is returned
    return $default;
  }

  /**
   * Get any currently existing manifest
   *
   * @param $sourceFile
   * @param null $associative force to return an associative array
 *
   * @return false|mixed
   *
   */
  public function checkManifest($sourceFile, $associative = NULL): mixed {
    if (!file_exists($sourceFile)) {
      return FALSE;
    }
    try {
      $result = $this->executeCommand($sourceFile);
    }
    catch (RuntimeException $e) {
      $this->logger->debug($e->getMessage() . ': ' . $sourceFile);
      return FALSE;
    }

    return json_decode($result, $associative);
  }

}
