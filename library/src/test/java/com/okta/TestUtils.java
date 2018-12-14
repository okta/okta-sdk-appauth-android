package com.okta;

import android.net.Uri;
import android.util.Base64;

import net.openid.appauth.AuthorizationRequest;
import net.openid.appauth.AuthorizationServiceConfiguration;
import net.openid.appauth.AuthorizationServiceDiscovery;
import net.openid.appauth.ResponseTypeValues;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.AbstractExecutorService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

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
    public static final String TEST_BASE = "http://test.openid.com/";

    public static final List<String> TEST_SCOPES_SUPPORTED = Arrays.asList("openid", "profile");
    public static final String REVOKE_URI = "/o/oauth/revoke";
    public static final String TEST_CODE_VERIFIER = "0123456789_0123456789_0123456789_0123456789";
    public static final String TEST_REVOKE_ENDPOINT = "http://test.openid.com" + REVOKE_URI;
    public static final String TEST_AUTHORIZATION_ENDPOINT = "o/oauth/auth";
    public static final String TEST_TOKEN_ENDPOINT = "o/oauth/token";
    static final String TEST_USERINFO_ENDPOINT = "o/oauth/userinfo";
    static final String TEST_REGISTRATION_ENDPOINT = "o/oauth/register";
    static final String TEST_END_OF_SESSION_ENDPOINT = "o/oauth/logout";
    static final String TEST_JWKS_URI = "o/oauth/jwks";
    static final List<String> TEST_RESPONSE_TYPES_SUPPORTED = Arrays.asList("code", "token");
    static final List<String> TEST_SUBJECT_TYPES_SUPPORTED = Arrays.asList("public");
    static final List<String> TEST_ID_TOKEN_SIGNING_ALG_VALUES = Arrays.asList("RS256");
    static final List<String> TEST_TOKEN_ENDPOINT_AUTH_METHODS
            = Arrays.asList("client_secret_post", "client_secret_basic");
    static final List<String> TEST_CLAIMS_SUPPORTED = Arrays.asList("aud", "exp");

    static final String TEST_SUBJECT = "SUBJ3CT";
    static final String TEST_AUDIENCE = "AUDI3NCE";

    private static String generateTestJson(String baseUrl) {
        return "{\n"
                + " \"issuer\": \"" + baseUrl + "\",\n"
                + " \"authorization_endpoint\": \"" + baseUrl+TEST_AUTHORIZATION_ENDPOINT + "\",\n"
                + " \"token_endpoint\": \"" + baseUrl+TEST_TOKEN_ENDPOINT + "\",\n"
                + " \"userinfo_endpoint\": \"" + baseUrl+TEST_USERINFO_ENDPOINT + "\",\n"
                + " \"end_session_endpoint\": \"" + baseUrl+TEST_END_OF_SESSION_ENDPOINT + "\",\n"
                + " \"registration_endpoint\": \"" + baseUrl+TEST_REGISTRATION_ENDPOINT + "\",\n"
                + " \"jwks_uri\": \"" + baseUrl+TEST_JWKS_URI + "\",\n"
                + " \"response_types_supported\": " + toJson(TEST_RESPONSE_TYPES_SUPPORTED) + ",\n"
                + " \"subject_types_supported\": " + toJson(TEST_SUBJECT_TYPES_SUPPORTED) + ",\n"
                + " \"id_token_signing_alg_values_supported\": "
                + toJson(TEST_ID_TOKEN_SIGNING_ALG_VALUES) + ",\n"
                + " \"scopes_supported\": " + toJson(TEST_SCOPES_SUPPORTED) + ",\n"
                + " \"token_endpoint_auth_methods_supported\": "
                + toJson(TEST_TOKEN_ENDPOINT_AUTH_METHODS) + ",\n"
                + " \"claims_supported\": " + toJson(TEST_CLAIMS_SUPPORTED) + "\n"
                + "}";
    }
// >>>>>>> Added native login flow

    private static String generateTokenResponseJson() {
        return "{" +
                "\"access_token\":\"eyJraWQiOiJHYjl2VDBSS0xPWjYyYmN6WVFJckJtY0FBYkVUcDJaVTdudWVCVFlsUkdVIiwiYWxnIjoiUlMyNTYifQ.eyJ2ZXIiOjEsImp0aSI6IkFULlY4UmdqQUhabWFXUzkxZEFORHpJNmFFdVVFeDNHYUpXTVdzXzExMlRPRjAiLCJpc3MiOiJodHRwczovL2xvaGlrYS11bS5va3RhcHJldmlldy5jb20vb2F1dGgyL2RlZmF1bHQiLCJhdWQiOiJhcGk6Ly9kZWZhdWx0IiwiaWF0IjoxNTQ1NDAwMDIxLCJleHAiOjE1NDU0ODY0MjEsImNpZCI6IjBvYWhuemhzZWd6WWpxRVRjMGg3IiwidWlkIjoiMDB1aHR3c3JyaUFDNXVpNDcwaDciLCJzY3AiOlsib3BlbmlkIiwicHJvZmlsZSJdLCJzdWIiOiJpbWFydHNla2hhQGxvaGlrYS5jb20ifQ.Bp-r0st5yyMFLKqoheh3mUTH_JhqubfBWXABWwApBoB_QqMB05EDskIBAhKfyc3KGMynoBK7fftP1KwNBhznYBQWUeueyXb5oHhKkPDYj8ds5Leu4758gLIDW2Ybj_eWspCR6aC1-eGWQZ-IbMz_rEpElmYC9TTXRPFngderPvqNW3dFU7VNJN-NFI18qEMRNf8-bIS8Qp9M1cU0WGKGi1wFDdgPM3761_R8beGMlWvulyA9B6mxZUs7M-ZxivJIdFbCKoFvxBo54ZBWXeMe-moEJA_tzXEuZf-Rq0mETwma-zBDCUWN3unZ51KRqEAtnZzGKDnt58on-olztbj1eA\"," +
                "\"token_type\":\"Bearer\"," +
                "\"expires_in\":86400," +
                "\"scope\":\"openid profile\"," +
                "\"id_token\":\"eyJraWQiOiJHYjl2VDBSS0xPWjYyYmN6WVFJckJtY0FBYkVUcDJaVTdudWVCVFlsUkdVIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiIwMHVodHdzcnJpQUM1dWk0NzBoNyIsIm5hbWUiOiJJaG9yIE1hcnRzZWtoYSIsInZlciI6MSwiaXNzIjoiaHR0cHM6Ly9sb2hpa2EtdW0ub2t0YXByZXZpZXcuY29tL29hdXRoMi9kZWZhdWx0IiwiYXVkIjoiMG9haG56aHNlZ3pZanFFVGMwaDciLCJpYXQiOjE1NDU0MDAwMjEsImV4cCI6MTU0NTQwMzYyMSwianRpIjoiSUQuVVdvSVZ1NVlCOXJCdzQ1MVhQS1NOYXdwWlpqNlQzY3IwaG9LUUlUa2VCWSIsImFtciI6WyJwd2QiXSwiaWRwIjoiMDBvM2V1Z3FxNG91bFVTeEowaDciLCJub25jZSI6IndIbDRTTUJua0lVRzZSRzd5REVrWHciLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJpbWFydHNla2hhQGxvaGlrYS5jb20iLCJhdXRoX3RpbWUiOjE1NDUzOTk5NzEsImF0X2hhc2giOiJPX0dHTm9TZnhSZTlucmRoZmFKdkNRIn0.JQBTltkijMyICl-UFWFgxM5av7xdsOec7m_t8lZ5bg3efb27RsYZPKJnSUX2g2um-CFsQfeoX22NGSvi1Wlx5OfoZLTkcgyzSxmS-ffxBen_zLDnNKAJtXZOMERDul_K3RANr8JhkmfQPgff6Qi8pCSr-5CceMbtXP5FTr7Jj14s4W8fgjgkauhw5-IKE8G8VfS_jq-omaxEwzqOU1uT-ZY5DX7vNMat5pRrbR01WFRzNnzH2lHhCTF2wPQtZly2RdBj5oGYRPMD5N7n5eCxTic3RVlA99ngI-uvhCxVynHeX2-SC1Nxyllz5GKrZCtcv0SQwrkbCQLWI7uw5WUF-g\"" +
                "}";
    }

    private static String toJson(List<String> strings) {
        return new JSONArray(strings).toString();
    }


    public static AuthorizationServiceDiscovery getTestDiscoveryDocument(String baseUrl) {
        try {
            return new AuthorizationServiceDiscovery(
                    new JSONObject(generateTestJson(baseUrl)));
        } catch (JSONException | AuthorizationServiceDiscovery.MissingArgumentException ex) {
            throw new RuntimeException("Unable to create test authorization service discover document", ex);
        }
    }

    public static AuthorizationServiceConfiguration getTestServiceConfig() {
        return getTestServiceConfig(TEST_BASE);
    }
    public static AuthorizationServiceConfiguration getTestServiceConfig(String baseUrl) {
        return new AuthorizationServiceConfiguration(getTestDiscoveryDocument(baseUrl));
    }

    public static AuthorizationRequest.Builder getMinimalAuthRequestBuilder(String baseUrl, String responseType) {
        return new AuthorizationRequest.Builder(
                getTestServiceConfig(baseUrl),
                TEST_CLIENT_ID,
                responseType,
                TEST_APP_REDIRECT_URI);
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

    public static String getValidTokenResponse(String baseUrl, String nonce) {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);

        Map<String,Object> additionalParameters = new HashMap<>();
        additionalParameters.put("nonce", nonce);
        String jws = Jwts.builder()
                .setSubject(TEST_CLIENT_ID)
                .setAudience(TEST_CLIENT_ID)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 24*60*60*1000))
                .setIssuer(baseUrl+"/")
                .addClaims(additionalParameters)
                .signWith(keyPair.getPrivate()).compact();



        return "{" +
                "\"access_token\":\"eyJraWQiOiJHYjl2VDBSS0xPWjYyYmN6WVFJckJtY0FBYkVUcDJaVTdudWVCVFlsUkdVIiwiYWxnIjoiUlMyNTYifQ.eyJ2ZXIiOjEsImp0aSI6IkFULlY4UmdqQUhabWFXUzkxZEFORHpJNmFFdVVFeDNHYUpXTVdzXzExMlRPRjAiLCJpc3MiOiJodHRwczovL2xvaGlrYS11bS5va3RhcHJldmlldy5jb20vb2F1dGgyL2RlZmF1bHQiLCJhdWQiOiJhcGk6Ly9kZWZhdWx0IiwiaWF0IjoxNTQ1NDAwMDIxLCJleHAiOjE1NDU0ODY0MjEsImNpZCI6IjBvYWhuemhzZWd6WWpxRVRjMGg3IiwidWlkIjoiMDB1aHR3c3JyaUFDNXVpNDcwaDciLCJzY3AiOlsib3BlbmlkIiwicHJvZmlsZSJdLCJzdWIiOiJpbWFydHNla2hhQGxvaGlrYS5jb20ifQ.Bp-r0st5yyMFLKqoheh3mUTH_JhqubfBWXABWwApBoB_QqMB05EDskIBAhKfyc3KGMynoBK7fftP1KwNBhznYBQWUeueyXb5oHhKkPDYj8ds5Leu4758gLIDW2Ybj_eWspCR6aC1-eGWQZ-IbMz_rEpElmYC9TTXRPFngderPvqNW3dFU7VNJN-NFI18qEMRNf8-bIS8Qp9M1cU0WGKGi1wFDdgPM3761_R8beGMlWvulyA9B6mxZUs7M-ZxivJIdFbCKoFvxBo54ZBWXeMe-moEJA_tzXEuZf-Rq0mETwma-zBDCUWN3unZ51KRqEAtnZzGKDnt58on-olztbj1eA\"," +
                "\"token_type\":\"Bearer\"," +
                "\"expires_in\":86400," +
                "\"scope\":\"openid profile\"," +
                "\"id_token\":\""+jws+"\"" +
                "}";
    }

    public static SSLSocketFactory getSSL(Object object) {
        try {
            /*
            * To generate keystore you should use next command
            * keytool -genkey -v -keystore mock.keystore.jks -alias okta_android_sdk -keyalg RSA -keysize 2048 -validity 10000
            * Copy mock.keystore.jks in folder library/src/test/resources
            * */
            URL filepath = object.getClass().getClassLoader().getResource("mock.keystore.jks");
            File file = new File(filepath.getPath());

            FileInputStream stream = new FileInputStream(file);
            char[] serverKeyStorePassword = "123456".toCharArray();
            KeyStore serverKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            serverKeyStore.load(stream, serverKeyStorePassword);

            String kmfAlgorithm = KeyManagerFactory.getDefaultAlgorithm();
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(kmfAlgorithm);
            kmf.init(serverKeyStore, serverKeyStorePassword);

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(kmfAlgorithm);
            trustManagerFactory.init(serverKeyStore);

            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
            return sslContext.getSocketFactory();
        } catch (Exception e) {
            return null;
        }
    }

    public static String getBaseUrl(Uri uri) {
        String baseUrl = uri.getScheme()+"://"+uri.getHost();
        if(uri.getPort() != -1) {
            baseUrl = baseUrl + ":"+uri.getPort();
        }
        return baseUrl;
    }

}
