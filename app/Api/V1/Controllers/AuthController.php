<?php

namespace App\Api\V1\Controllers;

use DB;
use GuzzleHttp\Client;
use JWTAuth;
use Mockery\CountValidator\Exception;
use PDO;
use TobyMaxham\Database\Connectors\DBLIBConnector;
use Tymon\JWTAuth\Token;
use Validator;
use Config;
use Illuminate\Http\Request;
use Illuminate\Mail\Message;
use Dingo\Api\Routing\Helpers;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Password;
use Tymon\JWTAuth\Exceptions\JWTException;
use Dingo\Api\Exception\ValidationHttpException;
use SoapClient;

class AuthController extends Controller
{
    use Helpers;

    public function status(Request $request)
    {
        $userData = $request->only(['phone']);
        if (starts_with($userData['phone'], "0")) {
            $userData['phone'] = "234" . substr($userData['phone'], 1);
        }

        $params = null;
        $myparams = array();

        if (env('APP_ENV', 'production') == 'local') {
            $query = "declare @result int exec goaltime_appcheckUsers {$userData['phone']}, @result output select @result as result";
        } else if (env('APP_ENV', 'production') == 'production') {
            $query = "exec goaltime_appcheckUsers @phone=?, @result=?";

            $myparams['phone'] = $userData['phone'];
            $myparams['result'] = 0;

// Set up the proc params array - be sure to pass the param by reference
            $params = array(
                array(&$myparams['phone'], SQLSRV_PARAM_IN),
                array(&$myparams['result'], SQLSRV_PARAM_OUT)
            );
        }

        $row = self::callRaw($query, $params);
        if ($params) {
            $row = $myparams;
        }

        $result = $row ? $row['result'] : null;

        if ($result == 2) {
            $success = true;
            $message = "Phone number is already registered";
        } else if ($result == 3) {
            $success = true;
            $message = "SMS Registered";
        } else if ($result == 20) {
            return response()->json(['success' => false, 'message' => 'We are currently undergoing a System maintenance. Please check back later']);
        } else {
            $success = true;
            $message = "Unregistered";
        }


        return response()->json(['success' => $success, 'status' => $result, 'message' => $message]);
        //self::registerReadyCash();
        //return response()->json(['success' => 'success', 'status' => 'result', 'message' => 'message']);
    }

    public function login(Request $request)
    {
        $ip = $_SERVER['REMOTE_ADDR'];
        if (array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER)) {
            $exploded = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ip = array_pop($exploded);
        }
        $url = "http://ipinfo.io/{$ip}";
        $details = json_decode(file_get_contents($url));
        $country = $details->country;
        //echo $country;

        if ($country != "NG" && $country != "KE") {
            return response()->json(['success' => false, 'message' => "Sorry. You do not have permission to use this application from this country: ${country}"]);
        }

        $credentials = $request->only(['phone', 'password']);

        if (starts_with($credentials['phone'], "0")) {
            $credentials['phone'] = "234" . substr($credentials['phone'], 1);
        }

        $credentials['password'] = password_hash($credentials['password'], PASSWORD_BCRYPT, array(
            'salt' => env('SALT'),
            'cost' => 12,
        ));

        //echo $credentials['password'];

        $params = null;
        $myparams = array();

        if (env('APP_ENV', 'production') == 'local') {
            $query = "DECLARE @result int exec goaltime_userLogin {$credentials['phone']},'{$credentials['password']}',@result output select @result as result";
        } else if (env('APP_ENV', 'production') == 'production') {
            $query = "exec goaltime_userLogin @phone=?, @pass=?, @result=?";

            $myparams['phone'] = $credentials['phone'];
            $myparams['password'] = $credentials['password'];
            $myparams['result'] = 0;

// Set up the proc params array - be sure to pass the param by reference
            $params = array(
                array(&$myparams['phone'], SQLSRV_PARAM_IN),
                array(&$myparams['password'], SQLSRV_PARAM_IN),
                array(&$myparams['result'], SQLSRV_PARAM_OUT)
            );
        }

        $row = self::callRaw($query, $params);

        $profile = $row;
        $firstname = "";
        $lastname = "";
        $email = "";

        if ($params) {
            $row = $myparams;
        }

        $result = $row['result'];

        if ($result == 1) {
            try {
                $success = true;
                $payload = JWTAuth::manager()->getPayloadFactory()->make(
                    array_merge([], ['sub' => json_encode($credentials['phone'])])
                );
                //$payload = JWTAuth::makePayload($result);

                $token = JWTAuth::manager()->encode($payload)->get();
                $firstname = $profile[1]['firstname'];
                $lastname = $profile[1]['lastname'];
                $email = $profile[1]['email'];
                //JWTAuth::fromUser($result);
            } catch (JWTException $e) {
                return $this->response->error('could_not_create_token', 500);
            }
        } else if ($result == 20) {
            return response()->json(['success' => false, 'message' => 'We are currently undergoing a System maintenance. Please check back later']);
        } else {
            return $this->response->errorUnauthorized();
        }

        return response()->json(['success' => true, 'message' => $token, 'phone' => $credentials['phone'], 'firstname' => $firstname, 'lastname' => $lastname, 'email' => $email]);
    }

    public function updateProfile(Request $request)
    {
        $userData = $request->only(['token', 'email', 'firstname', 'lastname']);

        $phone = self::getPhoneFromToken($userData['token']);
        if (starts_with($phone, "0")) {
            $phone = "234" . substr($phone, 1);
        }

        $params = null;
        $myparams = array();

        if (env('APP_ENV', 'production') == 'local') {
            $query = "DECLARE @result int exec goaltime_appupdateaddUsers {$userData['firstname']}, {$userData['lastname']}, {$userData['phone']}, {$userData['email']},@result output select @result as result";
        } else if (env('APP_ENV', 'production') == 'production') {
            $query = "exec goaltime_appupdateaddUsers @fname=?, @lname=?, @phone=?, @email=?, @result=?";

            $myparams['fname'] = $userData['firstname'];
            $myparams['lname'] = $userData['lastname'];
            $myparams['phone'] = $phone;
            $myparams['email'] = $userData['email'];
            $myparams['result'] = 0;

// Set up the proc params array - be sure to pass the param by reference
            $params = array(
                array(&$myparams['fname'], SQLSRV_PARAM_IN),
                array(&$myparams['lname'], SQLSRV_PARAM_IN),
                array(&$myparams['phone'], SQLSRV_PARAM_IN),
                array(&$myparams['email'], SQLSRV_PARAM_IN),
                array(&$myparams['result'], SQLSRV_PARAM_OUT)
            );
        }

        $row = self::callRaw($query, $params);

        $profile = $row;
        $firstname = "";
        $lastname = "";
        $email = "";

        if ($params) {
            $row = $myparams;
        }

        $result = $row['result'];

        if ($result == 1) {
            $success = true;
            $message = "Profile Update Successful";
            $firstname = $userData['firstname'];
            $lastname = $userData['lastname'];
            $email = $userData['email'];
        } else if ($result == 20) {
            return response()->json(['success' => false, 'message' => 'We are currently undergoing a System maintenance. Please check back later']);
        } else {
            return response()->json(['success' => false, 'message' => 'Profile Update Failed. Pls try Later!']);
        }

        return response()->json(['success' => true, 'message' => $message, 'firstname' => $firstname, 'lastname' => $lastname, 'email' => $email]);
    }

    /**
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function signup(Request $request)
    {
        $signupFields = Config::get('boilerplate.signup_fields');
        $hasToReleaseToken = Config::get('boilerplate.signup_token_release');

        $userData = $request->only($signupFields);
        if (starts_with($userData['phone'], "0")) {
            $userData['phone'] = "234" . substr($userData['phone'], 1);
        }
        $userData['password'] = password_hash($userData['password'], PASSWORD_BCRYPT, array(
            'salt' => env('SALT'),
            'cost' => 12,
        ));

        $params = null;
        $myparams = array();

        if (env('APP_ENV', 'production') == 'local') {
            $query = "DECLARE @result int exec goaltime_appcheckUsers {$userData['phone']},@result output select @result as result";
        } else if (env('APP_ENV', 'production') == 'production') {
            $query = "exec goaltime_appcheckUsers @phone=?, @result=?";

            $myparams['phone'] = $userData['phone'];
            $myparams['result'] = 0;

// Set up the proc params array - be sure to pass the param by reference
            $params = array(
                array(&$myparams['phone'], SQLSRV_PARAM_IN),
                array(&$myparams['result'], SQLSRV_PARAM_OUT)
            );
        }

        $row = self::callRaw($query, $params);
        if ($params) {
            $row = $myparams;
        }

        $result = $row['result'];
        $message = null;

        if ($result == 2) {
            $success = false;
            $message = 'Phone number is already registered';
            return response()->json(['success' => $success, 'message' => $message]);
        } else if ($result == 3) {
            $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$&_-?";
            $userData['password'] = substr(str_shuffle($chars), 0, 8);
            $res = self::sendSms($userData['phone'], 'TIME2SCORE: Password Reset - New Password: ' . $userData['password'] . '. Pls change your password as soon as possible');
            //error_log($res->getBody());
            if ($res != "00") {
                $success = false;
                $message = 'Password reset failed. Unable to send SMS';
                return response()->json(['success' => $success, 'message' => $message]);
            }

            $userData['password'] = password_hash($userData['password'], PASSWORD_BCRYPT, array(
                'salt' => env('SALT'),
                'cost' => 12,
            ));
        } else if ($result == 20) {
            return response()->json(['success' => false, 'message' => 'We are currently undergoing a System maintenance. Please check back later']);
        }

        $params = null;

        if (env('APP_ENV', 'production') == 'local') {
            $query = "DECLARE @result int exec goaltime_appaddUsers {$userData['firstname']},{$userData['lastname']},{$userData['phone']},'{$userData['password']}','{$userData['email']}',@result output select @result as result";
        } else if (env('APP_ENV', 'production') == 'production') {
            $query = "exec goaltime_appaddUsers @fname=?, @lname=?, @phone=?, @pass=?, @email=?, @result=?";

            $myparams['firstname'] = $userData['firstname'];
            $myparams['lastname'] = $userData['lastname'];
            $myparams['phone'] = $userData['phone'];
            $myparams['password'] = $userData['password'];
            $myparams['email'] = $userData['email'];
            $myparams['result'] = 0;

// Set up the proc params array - be sure to pass the param by reference
            $params = array(
                array(&$myparams['firstname'], SQLSRV_PARAM_IN),
                array(&$myparams['lastname'], SQLSRV_PARAM_IN),
                array(&$myparams['phone'], SQLSRV_PARAM_IN),
                array(&$myparams['password'], SQLSRV_PARAM_IN),
                array(&$myparams['email'], SQLSRV_PARAM_IN),
                array(&$myparams['result'], SQLSRV_PARAM_OUT)
            );
        }

        $row = self::callRaw($query, $params);
        if ($params) {
            $row = $myparams;
        }

        $result = $row['result'];

        if ($result == 2) {
            $success = true;
            $message = $userData['phone'] . " was successfully registered";
        } else if ($result == 1) {
            $success = true;
            $message = 'Registration was successful and a New password sent. Please change password!';
        } else if ($result == 20) {
            return response()->json(['success' => false, 'message' => 'We are currently undergoing a System maintenance. Please check back later']);
        } else {
            $success = false;
            $message = "Unknown Error!";
        }

        return response()->json(['success' => $success, 'status' => $result, 'message' => $message]);
    }

    public function passwordReset(Request $request)
    {
        $userData = $request->only(['phone']);

        if (starts_with($userData['phone'], "0")) {
            $userData['phone'] = "234" . substr($userData['phone'], 1);
        }

        $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$&_-?";
        $userData['password'] = substr(str_shuffle($chars), 0, 8);

        $message = null;

        $res = self::sendSms($userData['phone'], 'TIME2SCORE: Password Reset - New Password: ' . $userData['password'] . '. Pls change your password as soon as possible');

        $userData['password'] = password_hash($userData['password'], PASSWORD_BCRYPT, array(
            'salt' => env('SALT'),
            'cost' => 12,
        ));

        //error_log($res->getBody());
        if ($res != "00") {
            $success = false;
            $message = 'Password reset failed. Unable to send SMS';
            return response()->json(['success' => $success, 'message' => $message]);
        }

        $params = null;

        if (env('APP_ENV', 'production') == 'local') {
            $query = "DECLARE @result int exec goaltime_appforgetUserspass {$userData['phone']}, '{$userData['password']}', @result output select @result as result";
        } else if (env('APP_ENV', 'production') == 'production') {
            $query = "exec goaltime_appforgetUserspass @phone=?, @pass=?, @result=?";

            $myparams['phone'] = $userData['phone'];
            $myparams['password'] = $userData['password'];
            $myparams['result'] = 0;

// Set up the proc params array - be sure to pass the param by reference
            $params = array(
                array(&$myparams['phone'], SQLSRV_PARAM_IN),
                array(&$myparams['password'], SQLSRV_PARAM_IN),
                array(&$myparams['result'], SQLSRV_PARAM_OUT)
            );
        }

        $row = self::callRaw($query, $params);
        if ($params) {
            $row = $myparams;
        }

        $result = $row['result'];

        if ($result == 1) {
            $success = true;
            $message = 'New password sent. Change Password Required';
        } else if ($result == 20) {
            return response()->json(['success' => false, 'message' => 'We are currently undergoing a System maintenance. Please check back later']);
        } else {
            $success = false;
            $message = "Password Reset Failed";
        }

        return response()->json(['success' => $success, 'message' => $message]);
    }

    public function changePassword(Request $request)
    {
        $userData = $request->only(['current', 'new', 'token']);

        $phone = self::getPhoneFromToken($userData['token']);
        if (starts_with($phone, "0")) {
            $phone = "234" . substr($phone, 1);
        }

        $userData['current'] = password_hash($userData['current'], PASSWORD_BCRYPT, array(
            'salt' => env('SALT'),
            'cost' => 12,
        ));

        $userData['new'] = password_hash($userData['new'], PASSWORD_BCRYPT, array(
            'salt' => env('SALT'),
            'cost' => 12,
        ));

        $params = null;
        $myparams = array();

        if (env('APP_ENV', 'production') == 'local') {
            $query = "DECLARE @result int exec goaltime_appchangeUserspass {$phone}, {$userData['current']}, {$userData['new']}, @result output select @result as result";
        } else if (env('APP_ENV', 'production') == 'production') {
            $query = "exec goaltime_appchangeUserspass @phone=?, @oldpass=?, @pass=?, @result=?";

            $myparams['phone'] = $phone;
            $myparams['oldpass'] = $userData['current'];
            $myparams['pass'] = $userData['new'];
            $myparams['result'] = 0;

// Set up the proc params array - be sure to pass the param by reference
            $params = array(
                array(&$myparams['phone'], SQLSRV_PARAM_IN),
                array(&$myparams['oldpass'], SQLSRV_PARAM_IN),
                array(&$myparams['pass'], SQLSRV_PARAM_IN),
                array(&$myparams['result'], SQLSRV_PARAM_OUT)
            );
        }

        $row = self::callRaw($query, $params);
        if ($params) {
            $row = $myparams;
        }

        $result = $row['result'];

        if ($result == 1) {
            $success = true;
            $message = "Password successfully changed";
        } else if ($result == 20) {
            return response()->json(['success' => false, 'message' => 'We are currently undergoing a System maintenance. Please check back later']);
        } else {
            $success = false;
            $message = "Invalid phone number or password";
        }

        return response()->json(['success' => $success, 'message' => $message]);
    }

    public function fixtures(Request $request)
    {
        $query = "exec goaltime_fixtures";
        $params = null;

        $row = self::callRaw($query, $params);
        if (!$row) {
            return response()->json(['success' => false, 'message' => 'No match fixture available']);
        }

        return response()->json(['success' => true, 'message' => $row]);
    }

    public function jackpot(Request $request)
    {
        $matchData = $request->only(['matchcode']);

        $params = null;
        $myparams = array();

        if (env('APP_ENV', 'production') == 'local') {
            $query = "DECLARE @jackpot int, @result int exec matchjackpot {$matchData['matchcode']},@jackpot output,@result output select @result as result, @jackpot as jackpot";
        } else if (env('APP_ENV', 'production') == 'production') {
            $query = "exec matchjackpot @matchcode=?, @jackpot=?, @result=?";

            $myparams['matchcode'] = $matchData['matchcode'];
            $myparams['jackpot'] = 0;
            $myparams['result'] = 0;

// Set up the proc params array - be sure to pass the param by reference
            $params = array(
                array(&$myparams['matchcode'], SQLSRV_PARAM_IN),
                array(&$myparams['jackpot'], SQLSRV_PARAM_OUT),
                array(&$myparams['result'], SQLSRV_PARAM_OUT)
            );
        }

        $row = self::callRaw($query, $params);
        if ($params) {
            $row = $myparams;
        }

        $result = $row['result'];

        if ($result == 1) {
            $success = true;
            $message = $row['jackpot'];
        } else if ($result == 20) {
            return response()->json(['success' => false, 'message' => 'We are currently undergoing a System maintenance. Please check back later']);
        } else {
            $success = false;
            $message = "Invalid match code or no jackpot available";
        }

        return response()->json(['success' => $success, 'message' => $message]);
    }

    public function creditwallet(Request $request)
    {
        $walletData = $request->only(['token', 'pin']);
        $phone = self::getPhoneFromToken($walletData['token']);
        if (starts_with($phone, "0")) {
            $phone = "234" . substr($phone, 1);
        }

        $params = null;
        $myparams = array();

        if (env('APP_ENV', 'production') == 'local') {
            $query = "Declare @newBal float, @promo float, @result int exec creditwallet {$phone},{$walletData['pin']}, @newBal output, @promo output, @result output select @result as result, @newBal as newBal, @promo as promo";
        } else if (env('APP_ENV', 'production') == 'production') {
            $query = "exec creditwallet @phone=?, @pin=?, @result=?, @newBal=?, @promo=?";

            $myparams['phone'] = $phone;
            $myparams['pin'] = $walletData['pin'];
            $myparams['result'] = 0;
            $myparams['newBal'] = 0;
            $myparams['promo'] = 0;

// Set up the proc params array - be sure to pass the param by reference
            $params = array(
                array(&$myparams['phone'], SQLSRV_PARAM_IN),
                array(&$myparams['pin'], SQLSRV_PARAM_IN),
                array(&$myparams['result'], SQLSRV_PARAM_OUT),
                array(&$myparams['newBal'], SQLSRV_PARAM_OUT),
                array(&$myparams['promo'], SQLSRV_PARAM_OUT)
            );
        }

        $row = self::callRaw($query, $params);
        if ($params) {
            $row = $myparams;
        }

        $result = $row['result'];

        $success = null;
        $newBal = null;
        $promo = null;
        $message = null;

        if ($result == 1) {
            $success = false;
            $message = "Phone number is not registered";
        } else if ($result == 2) {
            $success = false;
            $message = "Pin already used";
        } else if ($result == 3) {
            $success = true;
            $newBal = $row['newBal'];
            $promo = $row['promo'];
            $message = "Wallet successfully credited. New Balance: {$newBal}, Promo: {$promo}";
        } else if ($result == 4) {
            $success = false;
            $message = "Invalid pin number";
        } else if ($result == 5) {
            $success = true;
            $message = "Pls contact admin for pin activation";
        } else if ($result == 20) {
            return response()->json(['success' => false, 'message' => 'We are currently undergoing a System maintenance. Please check back later']);
        }

        return response()->json(['success' => $success, 'status' => $result, 'newBalance' => $newBal, 'promo' => $promo, 'message' => $message]);
    }

    public function currentSlot(Request $request)
    {
        $matchData = $request->only(['matchcode']);

        $params = null;
        $myparams = array();

        if (env('APP_ENV', 'production') == 'local') {
            $query = "Declare @slot1 int, @slot2 int exec getcurrentSlot {$matchData['matchcode']}, @slot1 output, @slot2 output select @slot1 as slot1, @slot2 as slot2";
        } else if (env('APP_ENV', 'production') == 'production') {
            $query = "exec getcurrentSlot @matchcode=?, @slot1=?, @slot2=?";

            $myparams['matchcode'] = $matchData['matchcode'];
            $myparams['slot1'] = -1;
            $myparams['slot2'] = -1;

// Set up the proc params array - be sure to pass the param by reference
            $params = array(
                array(&$myparams['matchcode'], SQLSRV_PARAM_IN),
                array(&$myparams['slot1'], SQLSRV_PARAM_OUT),
                array(&$myparams['slot2'], SQLSRV_PARAM_OUT)
            );
        }

        $row = self::callRaw($query, $params);
        if ($params) {
            $row = $myparams;
        }

        if (!isset($row['slot2']) || $row['slot2'] < 0) {
            return response()->json(['success' => false, 'message' => 'Invalid match fixture or unable to get current slot']);
        }

        $homegoals = "";
        $awaygoals = "";
        $scores = simplexml_load_file('http://www.goalserve.com/getfeed/2ccdd8f42d2b499ab96c9d740773e60b/soccernew/home');
        foreach ($scores->category as $category):
            foreach ($category->matches as $matches):
                foreach ($matches->match as $match):
                    $matchcode = $match['static_id'];
                    if ($matchcode == $row['matchcode']) {
                        $homegoals = $match->localteam['goals'] . "";
                        $awaygoals = $match->visitorteam['goals'] . "";
                    }
                endforeach;
            endforeach;
        endforeach;

        return response()->json(['success' => true, 'message' => 'Success', 'slot1' => $row['slot1'], 'slot2' => $row['slot2'], 'homegoals' => $homegoals, 'awaygoals' => $awaygoals]);
    }

    public function predictGoaltime(Request $request)
    {
        $resp = $this->walletBalance($request);

        if (!json_decode($resp->getContent())->success) {
            return $resp;
        }

        $balance = json_decode($resp->getContent())->newBal;

        $predictData = $request->only(['token', 'matchcode', 'slots']);
        $slots = explode(",", $predictData['slots']);
        $betamount = count($slots) * 100;
        if ($betamount > $balance) {
            return response()->json(['success' => 'false', 'status' => 8, 'newBal' => $balance, 'message' => 'Insufficient wallet balance']);
        }

        sort($slots, SORT_NUMERIC);

        $resp = $this->currentSlot($request);

        if (!json_decode($resp->getContent())->success) {
            return $resp;
        }

        $currentSlot = json_decode($resp->getContent())->slot2;
        if ($slots[0] <= $currentSlot) {
            return response()->json(['success' => 'false', 'status' => 3, 'newBal' => $balance, 'message' => 'One or more of the slots chosen is already closed']);
        }

        $phone = self::getPhoneFromToken($predictData['token']);
        if (starts_with($phone, "0")) {
            $phone = "234" . substr($phone, 1);
        }

        $status = array();
        $messages = array();
        $success = null;
        $message = null;
        $newBal = null;
        $successCount = 0;

        foreach ($slots as $slot) {
            $params = null;
            $myparams = array();

            if (env('APP_ENV', 'production') == 'local') {
                $query = "Declare @team varchar, @preditTime varchar, @newbalance float, @result int  exec goaltime_apppredit {$phone},{$predictData['matchcode']}, {$slot}, @team output, @preditTime output, @newbalance output, @result output select @result as result, @team as team, @preditTime as preditTime, @newbalance as newbalance";
            } else if (env('APP_ENV', 'production') == 'production') {
                $query = "exec goaltime_apppredit @telephone=?, @matchcode=?, @slot=?, @result=?, @team=?, @preditTime=?, @newbalance=?";

                $myparams['phone'] = $phone;
                $myparams['matchcode'] = $predictData['matchcode'];
                $myparams['slot'] = $slot;
                $myparams['result'] = 0;
                $myparams['team'] = '';
                $myparams['preditTime'] = '';
                $myparams['newbalance'] = 0;
                //$myparams['promobalance'] = 0;
                //$myparams['winbalance'] = 0;

// Set up the proc params array - be sure to pass the param by reference
                $params = array(
                    array(&$myparams['phone'], SQLSRV_PARAM_IN),
                    array(&$myparams['matchcode'], SQLSRV_PARAM_IN),
                    array(&$myparams['slot'], SQLSRV_PARAM_IN),
                    array(&$myparams['result'], SQLSRV_PARAM_OUT),
                    array(&$myparams['team'], SQLSRV_PARAM_OUT),
                    array(&$myparams['preditTime'], SQLSRV_PARAM_OUT),
                    array(&$myparams['newbalance'], SQLSRV_PARAM_OUT)
                );
            }

            $row = self::callRaw($query, $params);

            if ($params) {
                $row = $myparams;
            }

            $result = $row['result'];

            if ($result == 1) {
                $message = "Phone number is not registered";
            } else if ($result == 2) {
                $message = "Invalid match code";
            } else if ($result == 3) {
                $message = "Slot already closed";
            } else if ($result == 4) {
                $newBal = $row['newbalance'];
                $successCount++;
                $message = "Prediction successfully placed";
            } else if ($result == 5) {
                $message = "Match already played";
            } else if ($result == 6) {
                $message = "Match postponed";
            } else if ($result == 7) {
                $message = "Match cancelled";
            } else if ($result == 8) {
                $message = "Insufficient wallet balance";
            } else if ($result == 9) {
                $message = "Disabled Account";
            } else if ($result == 20) {
                return response()->json(['success' => false, 'message' => 'We are currently undergoing a System maintenance. Please check back later']);
            }

            $messages[] = $message;
            $status[] = $result;
        }

        if ($successCount > 0) {
            $success = true;
        } else {
            $success = false;
        }

        return response()->json(['success' => $success, 'slots' => $slots, 'status' => $status, 'newBal' => $newBal, 'message' => $messages]);
    }

    public function matchWinningSlots(Request $request)
    {
        $matchData = $request->only(['matchcode']);

        $params = null;
        $myparams = array();

        if (env('APP_ENV', 'production') == 'local') {
            $query = "exec getMatchWinningSlot {$matchData['matchcode']}";
        } else if (env('APP_ENV', 'production') == 'production') {
            $query = "exec getMatchWinningSlot @matchcode=?";

            $myparams['matchcode'] = $matchData['matchcode'];

// Set up the proc params array - be sure to pass the param by reference
            $params = array(
                array(&$myparams['matchcode'], SQLSRV_PARAM_IN)
            );
        }

        $row = self::callRaw($query, $params);
        if ($params) {
            $row = $myparams;
        }

        if (!$row) {
            return response()->json(['success' => false, 'message' => 'No data']);
        }

        return response()->json(['success' => true, 'message' => $row]);
    }

    public function walletBalance(Request $request)
    {
        $userData = $request->only(['token']);
        $phone = self::getPhoneFromToken($userData['token']);
        if (starts_with($phone, "0")) {
            $phone = "234" . substr($phone, 1);
        }

        $params = null;
        $myparams = array();

        if (env('APP_ENV', 'production') == 'local') {
            $query = "declare @newBal float, @winnings float, @gamingbal float, @promobal float, @result int exec appwalletbal {$phone}, @newBal output, @result output select @result as result, @newBal as newBal, @winnings as winnings, @gamingbal as gamingbal, @promobal as promobal";
        } else if (env('APP_ENV', 'production') == 'production') {
            $query = "EXEC appwalletbal @phone=?, @newBal=?, @winnings=?, @gamingbal=?, @promobal=?, @result=?";

            $myparams['phone'] = $phone;
            $myparams['newBal'] = 0;
            $myparams['winnings'] = 0;
            $myparams['gamingbal'] = 0;
            $myparams['promobal'] = 0;
            $myparams['result'] = 0;

// Set up the proc params array - be sure to pass the param by reference
            $params = array(
                array(&$myparams['phone'], SQLSRV_PARAM_IN),
                array(&$myparams['newBal'], SQLSRV_PARAM_OUT),
                array(&$myparams['winnings'], SQLSRV_PARAM_OUT),
                array(&$myparams['gamingbal'], SQLSRV_PARAM_OUT),
                array(&$myparams['promobal'], SQLSRV_PARAM_OUT),
                array(&$myparams['result'], SQLSRV_PARAM_OUT)
            );
        }

        $row = self::callRaw($query, $params);
        if ($params) {
            //print_r($myparams);
            $row = $myparams;
            //print_r($row);
        }

        $result = $row['result'];

        $success = null;
        $message = null;
        $newBal = null;
        $promoBal = null;
        $winningsBal = null;

        if ($result == 1) {
            $success = false;
            $message = "Phone number is not registered";
        } else if ($result == 2) {
            $success = true;
            $newBal = $row['newBal'];
            $winningsBal = $row['winnings'];
            $gamingBal = $row['gamingbal'];
            $promoBal = $row['promobal'];
            $message = "Success";
        } else if ($result == 20) {
            return response()->json(['success' => false, 'message' => 'We are currently undergoing a System maintenance. Please check back later']);
        }

        return response()->json(['success' => $success, 'newBal' => $newBal, 'winningsBal' => $winningsBal, 'gamingBal' => $gamingBal, 'promoBal' => $promoBal, 'message' => $message]);
    }

    public function transfer(Request $request)
    {
        $transferData = $request->only(['token', 'destination', 'amount']);
        $phone = self::getPhoneFromToken($transferData['token']);
        if (starts_with($phone, "0")) {
            $phone = "234" . substr($phone, 1);
        }

        if (starts_with($transferData['destination'], "0")) {
            $transferData['destination'] = "234" . substr($transferData['destination'], 1);
        }

        $params = null;
        $myparams = array();

        if (env('APP_ENV', 'production') == 'local') {
            $query = "Declare @towalletballance float, @fromWalletballance float, @result int exec transfer_credit {$phone},{$transferData['destination']},{$transferData['amount']}, @towalletballance output, @fromWalletballance output, @result output select @result as result, @fromWalletballance as newBal, @towalletballance as destBal";
        } else if (env('APP_ENV', 'production') == 'production') {
            $query = "exec transfer_credit @fromphone=?, @ToPhoneNO=?, @Amount=?, @result=?, @towalletballance=?, @fromWalletballance=?";

            $myparams['phone'] = $phone;
            $myparams['destination'] = $transferData['destination'];
            $myparams['amount'] = $transferData['amount'];
            $myparams['result'] = 0;
            $myparams['newBal'] = 0;
            $myparams['destBal'] = 0;

// Set up the proc params array - be sure to pass the param by reference
            $params = array(
                array(&$myparams['phone'], SQLSRV_PARAM_IN),
                array(&$myparams['destination'], SQLSRV_PARAM_IN),
                array(&$myparams['amount'], SQLSRV_PARAM_IN),
                array(&$myparams['result'], SQLSRV_PARAM_OUT),
                array(&$myparams['destBal'], SQLSRV_PARAM_OUT),
                array(&$myparams['newBal'], SQLSRV_PARAM_OUT)
            );
        }

        $row = self::callRaw($query, $params);
        if ($params) {
            $row = $myparams;
        }

        $result = $row['result'];

        $success = null;
        $newBal = null;
        $message = null;

        if ($result == 0) {
            $success = false;
            $message = "Phone number is not registered";
        } else if ($result == 1) {
            $success = false;
            $message = "Destination Phone number is not registered";
        } else if ($result == 2) {
            $success = false;
            $message = "Insufficient Funds!";
        } else if ($result == 3) {
            $success = true;
            $newBal = $row['newBal'];
            $message = "Successful transfer of =N={$transferData['amount']} to {$transferData['destination']}. New Balance: =N={$newBal}";
            $destmessage = "=N={$transferData['amount']} has been credited to your wallet from {$phone}. Your wallet balance is =N={$row['destBal']}.";
            $res = self::sendSms($transferData['destination'], $destmessage);
        } else if ($result == 5) {
            $success = false;
            $message = "Your account is disabled";
        } else if ($result == 20) {
            return response()->json(['success' => false, 'message' => 'We are currently undergoing a System maintenance. Please check back later']);
        }

        return response()->json(['success' => $success, 'status' => $result, 'newBalance' => $newBal, 'message' => $message]);
    }

    public function cashout(Request $request)
    {
        $cashoutData = $request->only(['token', 'channel', 'amount']);
        $phone = self::getPhoneFromToken($cashoutData['token']);
        if (starts_with($phone, "0")) {
            $phone = "234" . substr($phone, 1);
        }

        $params = null;
        $myparams = array();

        if (env('APP_ENV', 'production') == 'local') {
            $query = "Declare @winbalance float, @totalbalance float, @result int exec appcashout {$phone},{$cashoutData['amount']},{$cashoutData['channel']}, @balance output, @result output select @result as result, @totalbalance as newBal, @winbalance as winningsBal";
        } else if (env('APP_ENV', 'production') == 'production') {
            $query = "exec appcashout @phone=?, @amount=?, @platform=?, @result=?, @winbalance=?, @totalbalance=?";

            $myparams['phone'] = $phone;
            $myparams['amount'] = $cashoutData['amount'];
            $myparams['channel'] = $cashoutData['channel'];
            $myparams['result'] = 0;
            $myparams['newBal'] = 0;
            $myparams['winningsBal'] = 0;

// Set up the proc params array - be sure to pass the param by reference
            $params = array(
                array(&$myparams['phone'], SQLSRV_PARAM_IN),
                array(&$myparams['amount'], SQLSRV_PARAM_IN),
                array(&$myparams['channel'], SQLSRV_PARAM_IN),
                array(&$myparams['result'], SQLSRV_PARAM_OUT),
                array(&$myparams['winningsBal'], SQLSRV_PARAM_OUT),
                array(&$myparams['newBal'], SQLSRV_PARAM_OUT)
            );
        }

        $row = self::callRaw($query, $params);
        if ($params) {
            $row = $myparams;
        }

        $result = $row['result'];

        $success = null;
        $newBal = null;
        $winningsBal = null;
        $message = null;

        if ($result == 0) {
            $success = false;
            $message = "Phone number is not registered";
        } else if ($result == 1) {
            $success = false;
            $message = "Your account is disabled";
        } else if ($result == 2) {
            $success = false;
            $message = "Insufficient Funds!";
        } else if ($result == 3) {
            $success = true;
            $newBal = $row['newBal'];
            $winningsBal = $row['winningsBal'];
            $message = "Successful cashout of =N={$cashoutData['amount']} via {$cashoutData['channel']}. New Balance: =N={$winningsBal}";
        } else if ($result == 20) {
            return response()->json(['success' => false, 'message' => 'We are currently undergoing a System maintenance. Please check back later']);
        }

        return response()->json(['success' => $success, 'status' => $result, 'newBalance' => $newBal, 'winningsBal' => $winningsBal, 'message' => $message]);
    }

    public function statistics(Request $request)
    {
        $statsData = $request->only(['matchcode']);

        $params = null;
        $myparams = array();

        if (env('APP_ENV', 'production') == 'local') {
            $query = "Declare @total int, @home int, @away int exec app_stat2 {$statsData['matchcode']}, @total output, @home output, @away output select @home as home, @away as away, @total as total";
        } else if (env('APP_ENV', 'production') == 'production') {
            $query = "exec app_stat2 @matchcode=?, @total=?, @home=?, @away=?";

            $myparams['matchcode'] = $statsData['matchcode'];
            $myparams['home'] = 0;
            $myparams['away'] = 0;
            $myparams['total'] = 0;
// Set up the proc params array - be sure to pass the param by reference
            $params = array(
                array(&$myparams['matchcode'], SQLSRV_PARAM_IN),
                array(&$myparams['total'], SQLSRV_PARAM_OUT),
                array(&$myparams['home'], SQLSRV_PARAM_OUT),
                array(&$myparams['away'], SQLSRV_PARAM_OUT)
            );
        }

        $row = self::callRaw($query, $params);
        if ($params) {
            $row = $myparams;
        }

        $success = true;
        $home = 0;
        $away = 0;
        $percentagewin = 0;
        $status = "";
        $homegoals = "";
        $awaygoals = "";
        $homegoalmins = "";
        $awaygoalmins = "";
        $total = $row['home'] + $row['away'];

        if ($total > 0) {
            $home = round(($row['home'] / $total) * 100, 1, PHP_ROUND_HALF_EVEN);
            $away = round(100 - $home, 1, PHP_ROUND_HALF_EVEN);
            $percentagewin = round(($row['total'] / $total) * 100, 1, PHP_ROUND_HALF_EVEN);
        }

        $scores = simplexml_load_file('http://www.goalserve.com/getfeed/2ccdd8f42d2b499ab96c9d740773e60b/soccernew/home');
        foreach ($scores->category as $category):
            foreach ($category->matches as $matches):
                foreach ($matches->match as $match):
                    $matchcode = $match['static_id'];
                    if ($matchcode == $row['matchcode']) {
                        $status = $match['status'] . "";
                        $homegoals = $match->localteam['goals'] . "";
                        $awaygoals = $match->visitorteam['goals'] . "";
                        foreach ($match->events as $events):
                            foreach ($events->event as $event):
                                if ($event['type'] == 'goal') {
                                    if ($event['team'] == 'localteam') {
                                        $homegoalmins .= $event['minute'] . "',";
                                    } else if ($event['team'] == 'visitorteam') {
                                        $awaygoalmins .= $event['minute'] . "',";
                                    }
                                }
                            endforeach;
                        endforeach;
                        break;
                    }
                endforeach;
            endforeach;
        endforeach;

        if (strlen($homegoalmins) > 0) {
            $homegoalmins = substr($homegoalmins, 0, strlen($homegoalmins) - 1);
        }

        if (strlen($awaygoalmins) > 0) {
            $awaygoalmins = substr($awaygoalmins, 0, strlen($awaygoalmins) - 1);
        }
        return response()->json(['success' => $success, 'home' => $home, 'away' => $away, 'percentagewin' => $percentagewin, 'status' => $status, 'homegoals' => $homegoals, 'awaygoals' => $awaygoals, 'homegoalmins' => $homegoalmins, 'awaygoalmins' => $awaygoalmins, 'message' => 'Success']);
    }

    public function history(Request $request)
    {
        $userData = $request->only(['token']);

        $phone = self::getPhoneFromToken($userData['token']);
        if (starts_with($phone, "0")) {
            $phone = "234" . substr($phone, 1);
        }

        if (env('APP_ENV', 'production') == 'local') {
            $query = "exec app_walletLog {$phone}";
        } else if (env('APP_ENV', 'production') == 'production') {
            $query = "exec app_walletLog @phone=?";

            $myparams['phone'] = $phone;

            $params = array(
                array(&$myparams['phone'], SQLSRV_PARAM_IN)
            );
        }

        $row = self::callRaw($query, $params);
        if (!$row) {
            return response()->json(['success' => false, 'message' => 'No data available']);
        }

        return response()->json(['success' => true, 'message' => $row]);
    }

    public function leagueTable(Request $request)
    {
        $leagueData = $request->only(['country']);

        $league = array();

        $i = 0;
        $tournamentname = "";
        $url = 'http://www.goalserve.com/getfeed/2ccdd8f42d2b499ab96c9d740773e60b/standings/' . $leagueData['country'] . '.xml';
        $standings = simplexml_load_file($url);
        foreach ($standings->tournament as $tournament):
            $tournamentname = $tournament['league'] . "";
            foreach ($tournament->team as $team):
                $data = array();
                $data['team'] = $team['name'] . "";
                $data['position'] = $team['position'] . "";
                $data['p'] = $team->overall['gp'] . "";
                $data['w'] = $team->overall['w'] . "";
                $data['d'] = $team->overall['d'] . "";
                $data['l'] = $team->overall['l'] . "";
                $data['points'] = $team->total['p'] . "";
                $league[$i] = $data;
                $i++;
            endforeach;
        endforeach;

        return response()->json(['success' => true, 'tournament' => $tournamentname, 'leaguetable' => $league]);
    }

    private static function callRaw($query, $params = null)
    {
        //print_r($params);
        $rows = array();
        if (env('APP_ENV', 'production') == 'local') {
            $con = mssql_connect(env('DB_HOST', 'localhost'), env('DB_USERNAME', 'forge'), env('DB_PASSWORD', ''));

            mssql_select_db(env('DB_DATABASE', 'forge'), $con);

            $result = mssql_query($query);

            do {
                while ($row = mssql_fetch_assoc($result)) {
                    // Handle record ...
                    error_log(json_encode($row));
                    $rows = $row;
                }
            } while (mssql_next_result($result));

            //mssql_free_statement($result);
            mssql_close($con);
        } else if (env('APP_ENV', 'production') == 'production') {
            $options = array("UID" => env('DB_USERNAME', 'forge'), "PWD" => env('DB_PASSWORD', ''), "Database" => env('DB_DATABASE', 'forge'));
            $con = sqlsrv_connect(env('DB_HOST', 'localhost'), $options);

            $result = sqlsrv_prepare($con, $query, $params);
            if (sqlsrv_execute($result)) {
                do {
                    while ($row = sqlsrv_fetch_array($result, SQLSRV_FETCH_ASSOC)) {
                        // Handle record ...
                        $rows[] = $row;
                    }
                } while ($res = sqlsrv_next_result($result));
            } else {
                print_r("could not execute");
                die(print_r(sqlsrv_errors(), true));
            }

            //error_log(json_encode($params));
        }

        //print_r($rows);
        return $rows;
    }

    private static function sendSms($phone, $msg)
    {
        $client = new Client();
        $res = $client->request('POST', 'http://v2nportal.com/sms/gateway/httpsend.php', [
            'form_params' => [
                'U' => 'DOTUN.AYANSIJI@SUPERIORGAMESNG.COM',
                'P' => '2BB57D03A70EF267DA4C1DC0D08992EE',
                'D' => $phone,
                'S' => '20120',
                'M' => urlencode($msg),
                'T' => '1',
                'MSGID' => '132DAREB'
            ]
        ]);
        //error_log($res->getBody());
        return trim($res->getBody());
    }

    private static function getPhoneFromToken($token)
    {
        $payload = JWTAuth::manager()->decode(new Token($token));
        return trim($payload['sub'], '"');
    }

    private static function registerReadyCash()
    {
        /*$soapURL = "http://62.173.32.26:8080/ws/api/1.0?wsdl";
        $soapParameters = Array('Username' => "mats@mats.com", 'Password' => "password", "PIN" => '1234');
        $soapFunction = "register";
        $soapFunctionParameters = Array('phoneNumber' => '07036284180', 'firstName' => "Sola", 'lastName' => "Akanmu", 'sex' => "Male", 'state' => 'Lagos');

        $soapClient = new SoapClient($soapURL, $soapParameters);

        $soapResult = $soapClient->__soapCall($soapFunction, $soapFunctionParameters);

        if (is_array($soapResult) && isset($soapResult['registerResult'])) {
            // Process result.
            echo $soapResult['registerResult'];
        } else {
            // Unexpected result
            if (function_exists("debug_message")) {
                echo("Unexpected soapResult for {$soapFunction}: " . print_r($soapResult, TRUE));
            }
        }*/
    }

}