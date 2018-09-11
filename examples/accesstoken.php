<?php
error_reporting(E_ALL);
require __DIR__.'/../Acl.php';

$acl = new Acl([
  'url' => 'https://acl.shenghuojia.com/',
  'brandid' => $_GET['brandid'],
  'secret' => $_GET['secret'],
  'appid' => $_GET['appid']
]);

$accessToken = $acl->getAccessToken();

var_dump($accessToken);
