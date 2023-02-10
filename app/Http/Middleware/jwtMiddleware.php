<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class jwtMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): (\Illuminate\Http\Response|\Illuminate\Http\RedirectResponse)  $next
     * @return \Illuminate\Http\Response|\Illuminate\Http\RedirectResponse
     */
    public function handle(Request $request, Closure $next)
    {
        $authorization = $request->header('Authorization');
        $jwt = explode('Bearer ', $authorization);
        $key = 'example_key';
        if($jwt){
            try{
            $decoded = JWT::decode($jwt[1], new Key($key, 'HS256'));
            return $next($request);
            }catch(\Exception){
                 return response()->json([
            'message' => 'Authentication failed'], 400);
            }
        }
        return response()->json([
            'message' => 'Authentication failed'], 400);
}
}
