<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
use Carbon\Carbon;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class ApiAuthController extends Controller
{   
    function __construct(){
        $this->middleware('auth:api')->only(['logout']);
        $this->middleware('jwt')->only(['consulta']);
        
    }
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    
    function register(Request $request){
        try{
        User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password)]);
        
        } catch(\Exception $e) {
            return response()->json(['message' => 'User not Created'], 418);
        }
        return response()->json(['message' => 'User Created'], 201);
    }
    
    function login(Request $request) {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);
        $credentials = request(['email', 'password']);
        if (!Auth::attempt($credentials)) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }
        $user = Auth::user();
        $tokenResult = $user->createToken('Access Token');
        $token = $tokenResult->token;
        $token->save();
        return response()->json([
            
            'access_token' => $tokenResult->accessToken,
            'token_type' => 'Bearer',
            'expires_at' => Carbon::parse($token->expires_at)->toDateTimeString()
        ], 200);
    }
    
    function consulta(Request $request){
        
        
        $response = Http::get("https://api.sunrise-sunset.org/json?lat=37.1611307&lng=-3.587447");
        $horasalida = substr(json_decode($response->body())->results->sunrise, 0, 1);
        $minsalida = substr(json_decode($response->body())->results->sunrise, 2, 2)*0.01;
        $horapuesta = substr(json_decode($response->body())->results->sunset, 0, 1)+12;
        $minpuesta = substr(json_decode($response->body())->results->sunset, 2, 2)*0.01;
        $horaactual = \Carbon\Carbon::parse(\Carbon\Carbon::now())->format('H');
        $minactual = \Carbon\Carbon::parse(\Carbon\Carbon::now())->format('i')*0.01;
        $horaactual+=$minactual;
        $x = ($horaactual-$horasalida)/($horapuesta-$horasalida);
         return response()->json([
             'cos' => cos($x),
             'sin' => sin($x),
             'hora' => $horaactual,
             'sunrise' => $horasalida+$minsalida,
             'sunset' => $horapuesta+$minpuesta,
             'sensor1' => rand(0, 100)*0.01,
             'sensor2' => rand(0, 100)*0.01,
             'sensor3' => rand(0, 100)*0.01,
             'sensor4' => rand(0, 100)*0.01,
             ], 
             200);
    }
    
    function logout(Request $request) {
        $request->user()->token()->revoke();
        return response()->json(['message' => 'Logged out']);
    }
    function decode(Request $request){
        //coger del header y pasar por middleware
        $authorization = $request->header('Authorization');
        $jwt = explode('Bearer ', $authorization);
        $key = 'example_key';
        if($jwt){
            try{
        $decoded = JWT::decode($jwt[1], new Key($key, 'HS256'));
        return response()->json([
            'token' => $decoded], 200);
            }
            catch(\Exception){
                 return response()->json([
            'message' => 'error'], 500);
            }
        }
    }
    function jwt(Request $request){
        $user = $request->input('user');
        $password = $request->input('password');
        if($user = 'pepe@pepe.pepe'){
        $key = 'example_key';
        $payload = [
            'user' => $user,
            'expires_at' => Carbon::now()->addHour(),
        ];
        $jwt = JWT::encode($payload, $key, 'HS256');
        return response()->json([
            'token' => $jwt], 200);
        }
        return response()->json([
            'message' => 'error'], 401);
    }
}
