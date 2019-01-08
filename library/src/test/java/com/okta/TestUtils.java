package com.okta;

import android.net.Uri;

import java.util.List;

import android.util.Base64;
import net.openid.appauth.*;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.Arrays;
import java.util.concurrent.AbstractExecutorService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Contains common test values which are useful across all tests.
 */
public class TestUtils {

    public static final String TEST_CLIENT_ID = "test_client_id";
    public static final String TEST_NONCE = "NONC3";
    public static final String TEST_APP_SCHEME = "com.test.app";
    public static final Uri TEST_APP_REDIRECT_URI = Uri.parse(TEST_APP_SCHEME + ":/oidc_callback");
    public static final Uri TEST_APP_DISCOVERY_URI = Uri.parse(TEST_APP_SCHEME
            + "/.well-known/openid-configuration");

    public static final String TEST_ISSUER = "https://test.issuer";
    public static final List<String> TEST_SCOPES_SUPPORTED = Arrays.asList("openid", "profile");

    public static final String REVOKE_URI = "/o/oauth/revoke";
    public static final String TEST_CODE_VERIFIER = "0123456789_0123456789_0123456789_0123456789";
    static final String TEST_AUTHORIZATION_ENDPOINT = "http://test.openid.com/o/oauth/auth";
    static final String TEST_TOKEN_ENDPOINT = "http://test.openid.com/o/oauth/token";
    public static final String TEST_REVOKE_ENDPOINT = "http://test.openid.com" + REVOKE_URI;
    static final String TEST_USERINFO_ENDPOINT = "http://test.openid.com/o/oauth/userinfo";
    static final String TEST_REGISTRATION_ENDPOINT = "http://test.openid.com/o/oauth/register";
    static final String TEST_END_OF_SESSION_ENDPOINT = "http://test.openid.com/o/oauth/logout";
    static final String TEST_JWKS_URI = "http://test.openid.com/o/oauth/jwks";
    static final List<String> TEST_RESPONSE_TYPES_SUPPORTED = Arrays.asList("code", "token");
    static final List<String> TEST_SUBJECT_TYPES_SUPPORTED = Arrays.asList("public");
    static final List<String> TEST_ID_TOKEN_SIGNING_ALG_VALUES = Arrays.asList("RS256");
    static final List<String> TEST_TOKEN_ENDPOINT_AUTH_METHODS
            = Arrays.asList("client_secret_post", "client_secret_basic");
    static final List<String> TEST_CLAIMS_SUPPORTED = Arrays.asList("aud", "exp");

    static final String TEST_SUBJECT = "SUBJ3CT";
    static final String TEST_AUDIENCE = "AUDI3NCE";

    public static final String TEST_JSON = "{\n"
            + " \"issuer\": \"" + TEST_ISSUER + "\",\n"
            + " \"authorization_endpoint\": \"" + TEST_AUTHORIZATION_ENDPOINT + "\",\n"
            + " \"token_endpoint\": \"" + TEST_TOKEN_ENDPOINT + "\",\n"
            + " \"userinfo_endpoint\": \"" + TEST_USERINFO_ENDPOINT + "\",\n"
            + " \"end_session_endpoint\": \"" + TEST_END_OF_SESSION_ENDPOINT + "\",\n"
            + " \"registration_endpoint\": \"" + TEST_REGISTRATION_ENDPOINT + "\",\n"
            + " \"jwks_uri\": \"" + TEST_JWKS_URI + "\",\n"
            + " \"response_types_supported\": " + toJson(TEST_RESPONSE_TYPES_SUPPORTED) + ",\n"
            + " \"subject_types_supported\": " + toJson(TEST_SUBJECT_TYPES_SUPPORTED) + ",\n"
            + " \"id_token_signing_alg_values_supported\": "
            + toJson(TEST_ID_TOKEN_SIGNING_ALG_VALUES) + ",\n"
            + " \"scopes_supported\": " + toJson(TEST_SCOPES_SUPPORTED) + ",\n"
            + " \"token_endpoint_auth_methods_supported\": "
            + toJson(TEST_TOKEN_ENDPOINT_AUTH_METHODS) + ",\n"
            + " \"claims_supported\": " + toJson(TEST_CLAIMS_SUPPORTED) + ",\n"
            + "\"revocation_endpoint\": \"" + TEST_REVOKE_ENDPOINT + "\"\n"
            + "}";


    private static String toJson(List<String> strings) {
        return new JSONArray(strings).toString();
    }


    public static AuthorizationServiceDiscovery getTestDiscoveryDocument() {
        try {
            return new AuthorizationServiceDiscovery(
                    new JSONObject(TEST_JSON));
        } catch (JSONException | AuthorizationServiceDiscovery.MissingArgumentException ex) {
            throw new RuntimeException("Unable to create test authorization service discover document", ex);
        }
    }

    public static AuthorizationServiceConfiguration getTestServiceConfig() {
        return new AuthorizationServiceConfiguration(getTestDiscoveryDocument());
    }


    public static ExecutorService buildSyncynchronesExecutorService() {
        return new AbstractExecutorService() {
            @Override
            public void shutdown() {

            }

            @Override
            public List<Runnable> shutdownNow() {
                return null;
            }

            @Override
            public boolean isShutdown() {
                return false;
            }

            @Override
            public boolean isTerminated() {
                return false;
            }

            @Override
            public boolean awaitTermination(long l, TimeUnit timeUnit) throws InterruptedException {
                return false;
            }

            @Override
            public void execute(Runnable runnable) {
                runnable.run();
            }
        };
    }

    public static String getUnsignedIdToken(){
        JSONObject header = new JSONObject();
        JsonUtil.put(header, "typ", "JWT");
        Long nowInSeconds = System.currentTimeMillis() / 1000;
        Long tenMinutesInSeconds = (long) (10 * 60);

        JSONObject claims = new JSONObject();
        JsonUtil.putIfNotNull(claims, "iss", TEST_ISSUER);
        JsonUtil.putIfNotNull(claims, "sub", TEST_SUBJECT);
        JsonUtil.putIfNotNull(claims, "aud", TEST_AUDIENCE);
        JsonUtil.putIfNotNull(claims, "exp", String.valueOf(nowInSeconds + tenMinutesInSeconds));
        JsonUtil.putIfNotNull(claims, "iat", String.valueOf(nowInSeconds));
        JsonUtil.putIfNotNull(claims, "nonce", TEST_NONCE);


        String encodedHeader = base64UrlNoPaddingEncode(header.toString().getBytes());
        String encodedClaims = base64UrlNoPaddingEncode(claims.toString().getBytes());
        return encodedHeader + "." + encodedClaims;
    }

    private static String base64UrlNoPaddingEncode(byte[] data) {
        return Base64.encodeToString(data, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
    }

    public static AuthorizationRequest.Builder getMinimalAuthRequestBuilder(String responseType) {
        return new AuthorizationRequest.Builder(
                getTestServiceConfig(),
                TEST_CLIENT_ID,
                responseType,
                TEST_APP_REDIRECT_URI);
    }

    public static AuthorizationRequest.Builder getTestAuthRequestBuilder() {
        return getMinimalAuthRequestBuilder(ResponseTypeValues.CODE)
                .setScopes(AuthorizationRequest.Scope.OPENID, AuthorizationRequest.Scope.EMAIL)
                .setCodeVerifier(TEST_CODE_VERIFIER);
    }

    public static AuthorizationRequest getTestAuthRequest() {
        return getTestAuthRequestBuilder()
                .setNonce(null)
                .build();
    }

    public static JSONObject addField(JSONObject object, String name, String value) throws JSONException {
        object.put(name, value);
        return object;
    }

}
