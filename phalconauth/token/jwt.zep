namespace PhalconAuth\Token;

/**
 * Phalconauth\Token JSON Web Token implementation
 *
 * Minimum implementation used by Realtime auth, based on this spec:
 * http://self-issued.info/docs/draft-jones-json-web-token-01.html.
 *
 * @author Neuman Vong <neuman@twilio.com>
 * @author Anant Narayanan <anant@php.net>
 * @author Paul Scarrone <paul@phalconphp.com> Converstion to Zephir
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link     https://github.com/firebase/php-jwt
 */

use \DomainException;
use \InvalidArgumentException;
use \UnexpectedValueException;
use \DateTime;
use PhalconAuth\Token\Jwt\BeforeValidException;
use PhalconAuth\Token\Jwt\ExpiredException;
use PhalconAuth\Token\Jwt\SignatureInvalidException;

class Jwt {
  /*
   * When checking nbf, iat or expiration times,
   * we want to provide some extra leeway time to
   * account for clock skew.
   */
  public leeway = 0;

  /*
   * Allow the current timestamp to be specified.
   * Useful for fixing a value within unit testing.
   *
   * Will default to PHP time() value if null.
   */
  public timestamp = null;

  public supported_algs = [
        "HS256": ["hash_hmac", "SHA256"],
        "HS512": ["hash_hmac", "SHA512"],
        "HS384": ["hash_hmac", "SHA384"],
        "RS256": ["openssl", "SHA256"],
        "RS384": ["openssl", "SHA384"],
        "RS512": ["openssl", "SHA512"]
    ];

  /*
   * Decodes a JWT string into a PHP object.
   *
   * @param string        jwt            The JWT
   * @param string|array  key            The key, or map of keys.
   *                                      If the algorithm used is asymmetric, this is the public key
   * @param array         allowed_algs   List of supported verification algorithms
   *                                      Supported algorithms are 'HS256', 'HS384', 'HS512' and 'RS256'
   *
   * @return object The JWT's payload as a PHP object
   *
   * @throws UnexpectedValueException     Provided JWT was invalid
   * @throws SignatureInvalidException    Provided JWT was invalid because the signature verification failed
   * @throws BeforeValidException         Provided JWT is trying to be used before it's eligible as defined by 'nbf'
   * @throws BeforeValidException         Provided JWT is trying to be used before it's been created as defined by 'iat'
   * @throws ExpiredException             Provided JWT has since expired, as defined by the 'exp' claim
   *
   * @uses jsonDecode
   * @uses urlsafeB64Decode
   */
  public function decode(string jwt, var key, array allowed_algs = []) -> object
  {
    var timestamp;
    if (is_null(this->timestamp)) {
      let timestamp = time();
    } else {
      let timestamp = this->timestamp;
    }

    if (empty(key)) {
        throw new InvalidArgumentException("Key may not be empty");
    }

    var tks = explode('.', jwt);
    if (count(tks) != 3) {
        throw new UnexpectedValueException("Wrong number of segments");
    }

    var headb64 = tks[0];
    var bodyb64 = tks[1];
    var cryptob64 = tks[2];

    var header = this->jsonDecode(this->urlsafeB64Decode(headb64));
    if (empty(this->supported_algs[header->alg])) {
        throw new UnexpectedValueException("Algorithm not supported");
    }
    if (!in_array(header->alg, allowed_algs)) {
        throw new UnexpectedValueException("Algorithm not allowed");
    }
    if (header === null) {
        throw new UnexpectedValueException("Invalid header encoding");
    }
    if (empty(header->alg)) {
        throw new UnexpectedValueException("Empty algorithm");
    }
    if (is_array(key) || key instanceof \ArrayAccess) {
        if (isset(header->kid)) {
            if (!isset(key[header->kid])) {
                throw new UnexpectedValueException("'kid' invalid, unable to lookup correct key");
            }
            let key = key[header->kid];
        } else {
            throw new UnexpectedValueException("'kid' empty, unable to lookup correct key");
        }
    }

    var payload = this->jsonDecode(this->urlsafeB64Decode(bodyb64));
    if (payload === null) {
        throw new UnexpectedValueException("Invalid claims encoding");
    }

    var sig = this->urlsafeB64Decode(cryptob64);
    if (sig === false) {
        throw new UnexpectedValueException("Invalid signature encoding");
    }

    // Check the signature
    if (!this->verify("headb64.bodyb64", sig, key, header->alg)) {
        throw new SignatureInvalidException("Signature verification failed");
    }

    // Check if the nbf if it is defined. This is the time that the
    // token can actually be used. If it"s not yet that time, abort.
    if (isset(payload->nbf) && payload->nbf > (timestamp + this->leeway)) {
        throw new BeforeValidException(
            "Cannot handle token prior to " . date(DateTime::ISO8601, payload->nbf)
        );
    }

    // Check that this token has been created before "now". This prevents
    // using tokens that have been created for later use (and haven"t
    // correctly used the nbf claim).
    if (isset(payload->iat) && payload->iat > (timestamp + this->leeway)) {
        throw new BeforeValidException(
            "Cannot handle token prior to " . date(DateTime::ISO8601, payload->iat)
        );
    }

    // Check if this token has expired.
    if (isset(payload->exp) && (timestamp - this->leeway) >= payload->exp) {
        throw new ExpiredException("Expired token");
    }

    return payload;
  }

  /*
   * Converts and signs a PHP object or array into a JWT string.
   *
   * @param object|array  payload    PHP object or array
   * @param string        key        The secret key.
   *                                  If the algorithm used is asymmetric, this is the private key
   * @param string        alg        The signing algorithm.
   *                                  Supported algorithms are 'HS256', 'HS384', 'HS512' and 'RS256'
   * @param mixed         keyId
   * @param array         head       An array with header elements to attach
   *
   * @return string A signed JWT
   *
   * @uses jsonEncode
   * @uses urlsafeB64Encode
   */
  public function encode(
    var payload,
    string key,
    string alg = "HS256",
    var keyId = null,
    array head = null
  ) -> string {
      var header = ["typ": "JWT", "alg": alg];
      if (keyId !== null) {
          let header["kid"] = keyId;
      }
      if (is_null(head) && is_array(head)) {
          let header = array_merge(head, header);
      }
      array segments = [];
      let segments[] = this->urlsafeB64Encode(this->jsonEncode(header));
      let segments[] = this->urlsafeB64Encode(this->jsonEncode(payload));
      string signing_input = implode('.', segments);

      var signature = this->sign(signing_input, key, alg);
      let segments[] = this->urlsafeB64Encode(signature);

      return implode('.', segments);
  }

  /*
   * Sign a string with a given key and algorithm.
   *
   * @param string            msg    The message to sign
   * @param string|resource   key    The secret key
   * @param string            alg    The signing algorithm.
   *                                  Supported algorithms are 'HS256', 'HS384', 'HS512' and 'RS256'
   *
   * @return string An encrypted message
   *
   * @throws DomainException Unsupported algorithm was specified
   */
  public function sign(string msg, var key, string alg = "HS256") -> string
  {
    if (empty(this->supported_algs[alg])) {
      throw new \DomainException("Algorithm not supported");
    }

    var method = this->supported_algs[alg][0];
    var algorithm = this->supported_algs[alg][1];
    switch(method) {
      case "hash_hmac":
          return hash_hmac(algorithm, msg, key, true);
      case "openssl":
          var signature = "";
          var success = openssl_sign(msg, signature, key, algorithm);
          if (!success) {
              throw new \DomainException("OpenSSL unable to sign data");
          } else {
              return signature;
          }
      default:
        return "";
    }
    return "";
  }

  /*
   * Verify a signature with the message, key and method. Not all methods
   * are symmetric, so we must have a separate verify and sign method.
   *
   * @param string            msg        The original message (header and body)
   * @param string            signature  The original signature
   * @param string|resource   key        For HS*, a string key works. for RS*, must be a resource of an openssl public key
   * @param string            alg        The algorithm
   *
   * @return bool
   *
   * @throws DomainException Invalid Algorithm or OpenSSL failure
   */
  private function verify(string msg, string signature, var key, string alg) -> boolean
  {
      if (empty(this->supported_algs[alg])) {
          throw new \DomainException("Algorithm not supported");
      }

      var method = this->supported_algs[alg][0];
      var algorithm = this->supported_algs[alg][1];
      switch(method) {
          case "openssl":
              var success = openssl_verify(msg, signature, key, algorithm);
              if (success === 1) {
                  return true;
              } elseif (success === 0) {
                  return false;
              }
              // returns 1 on success, 0 on failure, -1 on error.
              throw new \DomainException(
                  "OpenSSL error: " . openssl_error_string()
              );
          case "hash_hmac":
          default:
              var hash = hash_hmac(algorithm, msg, key, true);
              if (function_exists("hash_equals")) {
                  return hash_equals(signature, hash);
              }
              var len = min(this->safeStrlen(signature), this->safeStrlen(hash));

              long status = 0;
              int i = 0;
              for i in range(0, len) {
                if (status === 0) {
                  let status = (ord(signature[i]) ^ ord(hash[i]));
                }
              }
              if (status === 0) {
                let status = (this->safeStrlen(signature) ^ this->safeStrlen(hash));
              }

              return (status === 0);
      }
      return false;
  }

  /*
   * Decode a JSON string into a PHP object.
   *
   * @param string input JSON string
   *
   * @return object Object representation of JSON string
   *
   * @throws DomainException Provided string was invalid JSON
   */
  public function jsonDecode(string input) -> object
  {
    var obj;
    if (version_compare(PHP_VERSION, "5.4.0", ">=") && !(defined("JSON_C_VERSION") && PHP_INT_SIZE > 4)) {
      /** In PHP >=5.4.0, json_decode() accepts an options parameter, that allows you
       * to specify that large ints (like Steam Transaction IDs) should be treated as
       * strings, rather than the PHP default behaviour of converting them to floats.
       */
      let obj = json_decode(input, false, 512, JSON_BIGINT_AS_STRING);
    } else {
      /** Not all servers will support that, however, so for older versions we must
       * manually detect large ints in the JSON string and quote them (thus converting
       *them to strings) before decoding, hence the preg_replace() call.
       */
      int max_int_length = strlen((string) PHP_INT_MAX) - 1;
      var json_without_bigints = preg_replace("/:\s*(-?\d{".max_int_length.",})/", ": \"1\"", input);
      let obj = json_decode(json_without_bigints);
    }

    if (function_exists("json_last_error") && json_last_error()) {
      this->handleJsonError(json_last_error());
    } elseif (obj === null && input !== "null") {
      throw new \DomainException("Null result with non-null input");
    }
    return obj;
  }

  /*
   * Encode a PHP object into a JSON string.
   *
   * @param object|array input A PHP object or array
   *
   * @return string JSON representation of the PHP object or array
   *
   * @throws DomainException Provided object could not be encoded to valid JSON
   */
  public function jsonEncode(var input) -> string
  {
    var json = json_encode(input);
    if (function_exists("json_last_error") && json_last_error()) {
      this->handleJsonError(json_last_error());
    } elseif (json === "null" && input !== null) {
      throw new \DomainException("Null result with non-null input");
    }
    return json;
  }

  /*
   * Decode a string with URL-safe Base64.
   *
   * @param string input A Base64 encoded string
   *
   * @return string A decoded string
   */
  public function urlsafeB64Decode(string input) -> string
  {
      int remainder = strlen(input) % 4;
      if (remainder) {
          int padlen = 4 - remainder;
          let input .= str_repeat('=', padlen);
      }
      return base64_decode(strtr(input, '-_', '+/'));
  }

  /*
   * Encode a string with URL-safe Base64.
   *
   * @param string input The string you want encoded
   *
   * @return string The base64 encode of what you passed in
   */
  public function urlsafeB64Encode(string input) -> string
  {
      return str_replace("=", "", strtr(base64_encode(input), "+/", "-_"));
  }

  /*
   * Helper method to create a JSON error.
   *
   * @param int errno An error number from json_last_error()
   *
   * @return void
   */
  private function handleJsonError(int err) -> void
  {
      array messages = [
          JSON_ERROR_DEPTH: "Maximum stack depth exceeded",
          JSON_ERROR_STATE_MISMATCH: "Invalid or malformed JSON",
          JSON_ERROR_CTRL_CHAR: "Unexpected control character found",
          JSON_ERROR_SYNTAX: "Syntax error, malformed JSON",
          JSON_ERROR_UTF8: "Malformed UTF-8 characters" //PHP >= 5.3.3
      ];
      throw new \DomainException(
          isset(messages[err])
          ? messages[err]
          : "Unknown JSON error: " . err
      );
  }

  /*
   * Get the number of bytes in cryptographic strings.
   *
   * @param string
   *
   * @return int
   */
  private function safeStrlen(string str) -> int
  {
      if (function_exists("mb_strlen")) {
          return mb_strlen(str, "8bit");
      }
      return strlen(str);
  }
}
