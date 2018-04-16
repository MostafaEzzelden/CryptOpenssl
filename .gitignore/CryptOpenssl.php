<?php

namespace Hash;

class CryptOpenssl
{
    private static $asBinary = true;
    private static $cipher = 'DES-EDE3';
    private static $option = OPENSSL_RAW_DATA;

    private static $key = "YOUR PRIVATE KEY";

    /**
     * @param $data
     * @return string
     */
    public static function encrypt($data)
    {
        $key = self::genKey();

        $ivlen = openssl_cipher_iv_length(self::$cipher);
        $iv = openssl_random_pseudo_bytes($ivlen);
        $encData = openssl_encrypt($data, self::$cipher, $key, self::$option, $iv);
        $hmac = hash_hmac('sha256', $encData, $key, self::$asBinary);
        $ciphertext = base64_encode($iv.$hmac.$encData);
        return $ciphertext;
    }

    /**
     * @param $data
     * @return string
     */
    public static function decrypt($data)
    {
        $key = self::genKey();

        $ciphertext = base64_decode($data);
        $ivlen = openssl_cipher_iv_length(self::$cipher);
        $iv = substr($ciphertext, 0, $ivlen);
        $hmac = substr($ciphertext, $ivlen, 32);
        $ciphertext_raw = substr($ciphertext, $ivlen + 32);
        $decData = openssl_decrypt($ciphertext_raw, self::$cipher, $key, self::$option, $iv);
        $calcmac = hash_hmac('sha256', $ciphertext_raw, $key, self::$asBinary);

        if (hash_equals($hmac, $calcmac)) {
            return $decData;
        }
        return false;
    }

    private static function genKey()
    {
        $key = md5(self::$key, true);
        $key .= substr($key, 0, 8);
        return $key;
    }
}


echo CryptOpenssl::encrypt('welcome');
echo "<br/>";

echo CryptOpenssl::decrypt(CryptOpenssl::encrypt('welcome'));
