<?php

namespace App\Http\Controllers\API;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
class AuthController extends Controller
{

    /**
     * @OA\Post(
     *     path="/api/signup",
     *     summary="Register a new user",
     *     tags={"Auth"},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"name","email","password","password_confirmation"},
     *             @OA\Property(property="name", type="string"),
     *             @OA\Property(property="email", type="string", format="email"),
     *             @OA\Property(property="password", type="string", format="password"),
     *             @OA\Property(property="password_confirmation", type="string", format="password")
     *         )
     *     ),
     *     @OA\Response(response=201, description="Signed up successfully"),
     *     @OA\Response(response=422, description="Validation error")
     * )
     */
    function signup(Request $request)
    {
        $fields = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|confirmed'
        ]);

        $user = User::create($fields);

        $token = $user->createToken('AUTH-TOKEN');

        return response([
            'message' => 'signed up',
            'user' => $user,
            'token' => $token->plainTextToken
        ], 201);
    }

    /**
     * @OA\Post(
     *     path="/api/signin",
     *     summary="Authenticate user",
     *     tags={"Auth"},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email","password"},
     *             @OA\Property(property="email", type="string", format="email"),
     *             @OA\Property(property="password", type="string", format="password")
     *         )
     *     ),
     *     @OA\Response(response=201, description="Signed in successfully"),
     *     @OA\Response(response=401, description="Invalid credentials")
     * )
     */
    function signin(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string'
        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response([
                'message' => 'invalid credentials'
            ], 401);
        }

        $token = $user->createToken('AUTH-TOKEN');

        $response = [
            'message' => 'signed in',
            'user' => $user,
            'token' => $token->plainTextToken
        ];

        return response($response, 201);
    }

    /**
     * @OA\Post(
     *     path="/api/signout",
     *     summary="Logout user (revoke token)",
     *     tags={"Auth"},
     *     security={{"sanctum":{}}},
     *     @OA\Response(response=200, description="Signed out successfully"),
     *     @OA\Response(response=401, description="Unauthenticated")
     * )
     */
    function signout(Request $request)
    {
        $user = $request->user();
        $user->currentAccessToken()->delete();
        return [
            'message' => 'signed out'
        ];
    }
}
