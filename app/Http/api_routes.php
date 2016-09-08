<?php
	
$api = app('Dingo\Api\Routing\Router');

$api->version('v1', function ($api) {

	$api->post('auth/login', 'App\Api\V1\Controllers\AuthController@login');
	$api->post('auth/signup', 'App\Api\V1\Controllers\AuthController@signup');
	$api->get('auth/fixtures', 'App\Api\V1\Controllers\AuthController@fixtures');
	$api->post('auth/recovery', 'App\Api\V1\Controllers\AuthController@recovery');
	$api->post('auth/reset', 'App\Api\V1\Controllers\AuthController@reset');
	$api->post('auth/status', 'App\Api\V1\Controllers\AuthController@status');
	$api->post('auth/jackpot', 'App\Api\V1\Controllers\AuthController@jackpot');
	$api->post('auth/changePassword', 'App\Api\V1\Controllers\AuthController@changePassword');
	$api->post('auth/creditwallet', 'App\Api\V1\Controllers\AuthController@creditwallet');
	$api->post('auth/currentSlot', 'App\Api\V1\Controllers\AuthController@currentSlot');
	$api->post('auth/predictGoaltime', 'App\Api\V1\Controllers\AuthController@predictGoaltime');
	$api->post('auth/matchWinningSlots', 'App\Api\V1\Controllers\AuthController@matchWinningSlots');
	$api->post('auth/walletBalance', 'App\Api\V1\Controllers\AuthController@walletBalance');
	$api->post('auth/passwordReset', 'App\Api\V1\Controllers\AuthController@passwordReset');
	$api->post('auth/updateProfile', 'App\Api\V1\Controllers\AuthController@updateProfile');
    $api->post('auth/transfer', 'App\Api\V1\Controllers\AuthController@transfer');
    $api->post('auth/cashout', 'App\Api\V1\Controllers\AuthController@cashout');
    $api->post('auth/statistics', 'App\Api\V1\Controllers\AuthController@statistics');
    $api->post('auth/history', 'App\Api\V1\Controllers\AuthController@history');
    $api->post('auth/leagueTable', 'App\Api\V1\Controllers\AuthController@leagueTable');

	// example of protected route
	$api->get('protected', ['middleware' => ['api.auth'], function () {		
		return \App\User::all();
    }]);

	// example of free route
	$api->get('free', function() {
		return \App\User::all();
	});

});
