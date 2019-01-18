<?php
  namespace Fawno\Auth;

  use Cake\Auth\AbstractPasswordHasher;

  class DrupalPasswordHasher extends AbstractPasswordHasher {
    private $drupal_hash_count = 15;
    private $drupal_min_hash_count = 7;
    private $drupal_max_hash_count = 30;
    private $drupal_hash_length = 55;

    protected function _password_itoa64 () {
      return './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    }

    protected function _password_base64_encode ($input, $count) {
      $output = '';
      $i = 0;
      $itoa64 = $this->_password_itoa64();
      do {
        $value = ord($input[$i++]);
        $output .= $itoa64[$value & 0x3f];
        if ($i < $count) $value |= ord($input[$i]) << 8;
        $output .= $itoa64[($value >> 6) & 0x3f];
        if ($i++ >= $count) break;
        if ($i < $count) $value |= ord($input[$i]) << 16;
        $output .= $itoa64[($value >> 12) & 0x3f];
        if ($i++ >= $count) break;
        $output .= $itoa64[($value >> 18) & 0x3f];
      } while ($i < $count);

      return $output;
    }

    protected function _password_generate_salt ($count_log2) {
      $output = '$S$';
      $count_log2 = $this->_password_enforce_log2_boundaries($count_log2);
      $itoa64 =$this-> _password_itoa64();
      $output .= $itoa64[$count_log2];
      $output .= $this->_password_base64_encode($this->drupal_random_bytes(6), 6);
      return $output;
    }

    protected function _password_enforce_log2_boundaries ($count_log2) {
      if ($count_log2 < $this->drupal_min_hash_count) {
        return $this->drupal_min_hash_count;
      } elseif ($count_log2 > $this->drupal_max_hash_count) {
        return $this->drupal_max_hash_count;
      }

      return (int) $count_log2;
    }

    protected function _password_crypt ($algo, $password, $setting) {
      if (strlen($password) > 512) return false;
      $setting = substr($setting, 0, 12);

      if ($setting[0] != '$' || $setting[2] != '$') return false;
      $count_log2 = $this->_password_get_count_log2($setting);
      if ($count_log2 < $this->drupal_min_hash_count || $count_log2 > $this->drupal_max_hash_count) return false;
      $salt = substr($setting, 4, 8);
      if (strlen($salt) != 8) return false;

      $hash = hash($algo, $salt . $password, true);
      for ($count = 1 << $count_log2; $count; --$count) {
        $hash = hash($algo, $hash . $password, true);
      }

      $len = strlen($hash);
      $output =  $setting . $this->_password_base64_encode($hash, $len);
      $expected = 12 + ceil((8 * $len) / 6);
      return (strlen($output) == $expected) ? substr($output, 0, $this->drupal_hash_length) : false;
    }

    protected function _password_get_count_log2 ($setting) {
      $itoa64 = $this->_password_itoa64();
      return strpos($itoa64, $setting[3]);
    }

    public function hash ($password) {
      return $this->_password_crypt('sha512', $password, $this->_password_generate_salt($this->drupal_hash_count));
    }

    public function check ($password, $hashedPassword) {
      if (substr($hashedPassword, 0, 2) == 'U$') {
        $hashedPassword = substr($hashedPassword, 1);
        $password = md5($password);
      }

      $type = substr($hashedPassword, 0, 3);
      switch ($type) {
        case '$S$':
          $hash = $this->_password_crypt('sha512', $password, $hashedPassword);
          break;
        case '$H$':
        case '$P$':
          $hash = $this->_password_crypt('md5', $password, $hashedPassword);
          break;
        default:
          return false;
      }
      return ($hash && $hashedPassword == $hash);
    }

    public function needsRehash ($password) {
      if ((substr($password, 0, 3) != '$S$') || (strlen($password) != $this->drupal_hash_length)) return true;
      $count_log2 = $this->_password_enforce_log2_boundaries($this->drupal_hash_count);
      return ($this->_password_get_count_log2($password) !== $count_log2);
    }

    public function drupal_random_bytes ($count) {
      static $random_state, $bytes, $has_openssl;

      $missing_bytes = $count - strlen($bytes);

      if ($missing_bytes > 0) {
        if (!isset($has_openssl)) $has_openssl = function_exists('openssl_random_pseudo_bytes');

        if ($has_openssl) {
          $bytes .= openssl_random_pseudo_bytes($missing_bytes);
        } elseif ($fh = @fopen('/dev/urandom', 'rb')) {
          $bytes .= fread($fh, max(4096, $missing_bytes));
          fclose($fh);
        }

        if (strlen($bytes) < $count) {
          if (!isset($random_state)) {
            $random_state = print_r($_SERVER, true);
            if (function_exists('getmypid')) $random_state .= getmypid();
            $bytes = '';
          }

          do {
            $random_state = hash('sha256', microtime() . mt_rand() . $random_state);
            $bytes .= hash('sha256', mt_rand() . $random_state, true);
          } while (strlen($bytes) < $count);
        }
      }
      $output = substr($bytes, 0, $count);
      $bytes = substr($bytes, $count);
      return $output;
    }
  }
