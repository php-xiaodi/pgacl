<?php

/**
 *  Class for communicate with Access Controll Layer (ACL)
 *
 *  @author pysche[at]xiaodi.io
 *
 */

class Acl
{
  /**
   *  Server Url
   */
  private $_api = '';

  /**
   *  Brand id for Olay Wechat
   */
  private $_brandid = '';

  /**
   *  Secret for Olay Wechat
   */
  private $_secret = '';

  /**
   *  Wxappid for Olay Wechat
   */
  private $_wxappid = '';

  public function __construct($config)
  {
      $this->_api = $config['url'];
      $this->_brandid = $config['brandid'];
      $this->_secret = $config['secret'];
      $this->_wxappid = $config['appid'];
  }

  /**
   * Get Wechat Appid.
   *
   * @return string
   */
  public function appid()
  {
    return $this->_wxappid;
  }

  /**
   *  Get OAuth url when we need wechat user's openid
   *
   *  @param string $origin
   *  @param string $type
   *  @return string
   */
  public function getOauthUrl($origin, $type = 'base')
  {
    $url = $this->_api . 'acl/wx/oauth2/authorize?brandId=' . $this->_brandid . '&scope=snsapi_' . $type . '&url=' . urlencode($origin);

    if ($type === 'userinfo') {
      $url .= '&access_token=true';
    }

    return $url;
  }

  /**
   *  Get access token for Wechat app
   *
   *  @return string
   */
  public function getAccessToken()
  {
    $accessToken = null;
    $rs = $this->_request('acl/api/token', [
      'timestamp' => time(),
      'nonce' => rand(100000, 999999),
      'brandId' => $this->_brandid
    ]);

    if (isset($rs['access_token'])) {
      $accessToken = $rs['access_token'];
    }

    return $accessToken;
  }

  /**
   *  Sign the parameter `openid` from ACL
   *  To avoid hack attack by using only `openid` parameter in URI
   *
   *  @param string $openid
   *  @param string $code
   *  @param string $timestamp
   *  @return string
   */
  public function signOpenid($openid, $code, $timestamp)
  {
    return $this->_sign([
      'code' => $code,
      'timestamp' => $timestamp,
      'openid' => $openid
    ]);
  }

  public function member($openid, $accessToken)
  {
    $api = 'https://api.weixin.qq.com/sns/userinfo';
    $qstr = '?access_token=' . $accessToken . '&openid=' . $openid . '&lang=zh_CN';
    $options = [
      CURLOPT_URL => $api.$qstr,
      CURLOPT_POST           => false,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_HEADER         => false,
      CURLOPT_SSL_VERIFYPEER => false,
      CURLOPT_SSL_VERIFYHOST => false,
      CURLOPT_TIMEOUT        => 15
    ];

    $ch = curl_init();
    curl_setopt_array($ch, $options);
    $response = curl_exec($ch);
    $info = curl_getinfo($ch);
    curl_close($ch);

    $result = json_decode($response, true);

    return $result;
  }

  /**
   *  Get JSAPI Ticket for Wechat App
   *
   *  @param string $requestUri
   *  @return array
   */
  public function getJsapiTicket($requestUri = '', $nonce = null)
  {
    $result = [];
    $ticket = null;

    $rs = $this->_request('acl/api/ticket', [
      'type' => 'jsapi',
      'brandId' => $this->_brandid
    ]);

    if (isset($rs['ticket'])) {
      $ticket = $rs['ticket'];
    }

    $jsapiUrl = '';
    if ($ticket !== null) {
      $result['timestamp'] = (string)time();
      $result['noncestr'] = $nonce ? $nonce : (string)(rand(100000, 999999));

      $jsapiUrl = $requestUri ? $requestUri : ($_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . '://' . (isset($_SERVER['HTTP_X_FORWARDED_HOST']) ? $_SERVER['HTTP_X_FORWARDED_HOST'] : $_SERVER['HTTP_HOST']) . $_SERVER['REQUEST_URI'];

      $str = 'jsapi_ticket=' . $ticket . '&noncestr=' . $result['noncestr'];
      $str .= '&timestamp=' . $result['timestamp'] . '&url=' . $jsapiUrl;

      $result['sign'] = sha1($str);
    }

    return $result;
  }

  /**
   *  Complete an ACL http request
   *
   *  @param string $url
   *  @param array $params
   *  @return array
   */
  private function _request($url, array $params)
  {
    $result = array();

    $signParams = $params;
    if ($url === 'acl/api/userinfo') {
      unset($signParams['brandId']);
    }
    $params['signature'] = $this->_sign($signParams);
    $url = $this->_api . $url;
    $url .= '?' . http_build_query($params);

    $options = array(
      CURLOPT_URL => $url,
      CURLOPT_POST           => false,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_HEADER         => false,
      CURLOPT_SSL_VERIFYPEER => false,
      CURLOPT_SSL_VERIFYHOST => false,
      CURLOPT_TIMEOUT        => 15
    );

    $ch = curl_init();
    curl_setopt_array($ch, $options);
    $response = curl_exec($ch);
    $info = curl_getinfo($ch);
    curl_close($ch);

    try {
      $result = json_decode($response, true);  
    } catch (\Exception $e) {
      $result = null;
    }

    return $result;
  }

  /**
   *  Sign parameters for ACL requests
   *
   *  @param array $params
   */
  private function _sign(array $params)
  {
    $params['secret'] = $this->_secret;
    $arr = array_values($params);

    sort($arr, SORT_STRING);
    $str = join('', $arr);
    $sign = sha1($str);

    error_log('str: '.$str.','.var_export($params, true));

    return $sign;
  }
}
