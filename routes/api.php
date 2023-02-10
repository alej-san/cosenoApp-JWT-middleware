<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\ApiAuthController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

Route::post('login', [ApiAuthController::class, 'login']);
Route::get('logout', [ApiAuthController::class, 'logout']);
Route::get('consulta', [ApiAuthController::class, 'consulta']);
Route::get('jwt', [ApiAuthController::class, 'jwt']);
Route::get('decode', [ApiAuthController::class, 'decode']);

