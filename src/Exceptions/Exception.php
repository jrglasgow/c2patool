<?php

namespace Jrglasgow\C2paTool\Exceptions;

class Exception extends \Exception {

  /**
   * The Translatable message, $this->messageVariables contains the variables
   * array for the translation.
   *
   * @var string
   */
  protected string $mesageText;

  /**
   * The variables to be used in the translatable string.
   *
   * @var array
   */
  protected array $messageVariables;

  public function __construct(string $message = '', int $code = 0, ?Throwable $previous = NULL, string $message_text = '', $message_variables = []) {
    parent::__construct($message, $code, $previous);
    $this->mesageText = $message_text;
    $this->messageVariables = $message_variables;
  }

  /**
   * Return the rtanslatable string for the message text.
   *
   * @return string
   */
  public function getMessageText() {
    return $this->mesageText;
  }

  /**
   * Return the variables for the message.
   *
   * @return array
   */
  public function getMessageVariables() {
    return $this->messageVariables;
  }

}
