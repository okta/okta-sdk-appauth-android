/*
 * Copyright (c) 2017, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License,
 * Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the
 * License.
 */

package com.okta.appauth.android;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

/**
 * Working around an Android Studio bug where test resources aren't on the classpath.
 * <a href="https://issuetracker.google.com/issues/37003772">Bug is tracked here</a>.
 */
@SuppressWarnings("WeakerAccess")
public class ConfigurationStreams {

    public static final String EXAMPLE_JSON_CONFIG =
            "{" +
                    "  \"client_id\": \"example_client_id\"," +
                    "  \"redirect_uri\": \"com.okta.appauth.android.test:/oauth2redirect\"," +
                    "  \"end_session_redirect_uri\": \"com.okta.appauth.android.test:/logout\"," +
                    "  \"scopes\": [" +
                    "    \"openid\"," +
                    "    \"foo\"" +
                    "  ]," +
                    "  \"issuer_uri\": \"https://example.com/issuer\"" +
                    "}";

    public static InputStream getExampleConfiguration() {
        return new ByteArrayInputStream(EXAMPLE_JSON_CONFIG.getBytes());
    }

    public static final String OTHER_JSON_CONFIG =
            "{" +
                    "  \"client_id\": \"other_client_id\"," +
                    "  \"redirect_uri\": \"com.okta.appauth.android.test:/oauth2redirect\"," +
                    "  \"end_session_redirect_uri\": \"com.okta.appauth.android.test:/logout\"," +
                    "  \"scopes\": [" +
                    "    \"openid\"," +
                    "    \"bar\"" +
                    "  ]," +
                    "  \"issuer_uri\": \"https://example.com/other-issuer\"" +
                    "}";

    public static InputStream getOtherConfiguration() {
        return new ByteArrayInputStream(OTHER_JSON_CONFIG.getBytes());
    }

    public static final String INVALID_JSON_CONFIG =
            "{" +
                    "  \"client_id\": \"example_client_id\"," +
                    "  \"redirect_uri\": \"com.okta.appauth.android.test:/oauth2redirect\"," +
                    "  \"end_session_redirect_uri\": \"com.okta.appauth.android.test:/logout\"," +
                    "  \"scopes\": [" +
                    "  ]," +
                    "  \"issuer_uri\": \"https://example.com/issuer\"" +
                    "}";

    public static final String VALID_AUTHORIZATION_RESPONSE =
                    "{" +
                    "\"access_token\":\"aaabbbccc\"," +
                    "\"request\":{" +
                        "\"redirectUri\":\"com.test.app:\\/oidc_callback\"," +
                        "\"codeVerifierChallengeMethod\":\"S256\"," +
                        "\"responseType\":\"code\"," +
                        "\"clientId\":\"test_client_id\"," +
                        "\"configuration\":{" +
                            "\"tokenEndpoint\":\"http:\\/\\/test.openid.com\\/o\\/oauth\\/token\"," +
                            "\"endSessionEndpoint\":\"http:\\/\\/test.openid.com\\/o\\/oauth\\/logout\"," +
                            "\"discoveryDoc\":{" +
                                "\"response_types_supported\":[\"code\",\"token\"]," +
                                "\"end_session_endpoint\":\"http:\\/\\/test.openid.com\\/o\\/oauth\\/logout\"," +
                                "\"scopes_supported\":[\"openid\",\"profile\"]," +
                                "\"issuer\":\"https:\\/\\/test.issuer\"," +
                                "\"authorization_endpoint\":\"http:\\/\\/test.openid.com\\/o\\/oauth\\/auth\"," +
                                "\"userinfo_endpoint\":\"http:\\/\\/test.openid.com\\/o\\/oauth\\/userinfo\"," +
                                "\"claims_supported\":[\"aud\",\"exp\"]," +
                                "\"jwks_uri\":\"http:\\/\\/test.openid.com\\/o\\/oauth\\/jwks\"," +
                                "\"subject_types_supported\":[\"public\"]," +
                                "\"id_token_signing_alg_values_supported\":[\"RS256\"]," +
                                "\"registration_endpoint\":\"http:\\/\\/test.openid.com\\/o\\/oauth\\/register\"," +
                                "\"token_endpoint_auth_methods_supported\":[\"client_secret_post\",\"client_secret_basic\"]," +
                                "\"token_endpoint\":\"http:\\/\\/test.openid.com\\/o\\/oauth\\/token\"" +
                            "}," +
                            "\"authorizationEndpoint\":\"http:\\/\\/test.openid.com\\/o\\/oauth\\/auth\"," +
                            "\"registrationEndpoint\":\"http:\\/\\/test.openid.com\\/o\\/oauth\\/register\"" +
                        "}," +
                        "\"codeVerifier\":\"0123456789_0123456789_0123456789_0123456789\"," +
                        "\"codeVerifierChallenge\":\"3enf_l37ZgKZBTWbstHg194tpA1hh-LVku_HCRF-S6A\"," +
                        "\"scope\":\"openid email\"," +
                        "\"additionalParameters\":{}," +
                        "\"state\":\"$TAT3\"," +
                        "\"nonce\":\"Zlvp5IFSsB8zuAj1c8lJbQ\"" +
                    "}," +
                    "\"code\":\"zxcvbnmjk\"," +
                    "\"expires_at\":78023," +
                    "\"id_token\":\"eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiJTVUJKM0NUIiwiYXVkIjoidGVzdF9jbGllbnRfaWQ" +
                    "iLCJpc3MiOiJodHRwczpcL1wvdGVzdC5pc3N1ZXIiLCJleHAiOiIxNTQzOTM1OTIxIiwiaWF0IjoiMTU0MzkzN" +
                    "TMyMSJ9\"," +
                    "\"additional_parameters\":{}," +
                    "\"state\":\"$TAT3\"," +
                    "\"token_type\":\"bearer\"" +
                    "}";

    public static InputStream getInvalidConfiguration() {
        return new ByteArrayInputStream(INVALID_JSON_CONFIG.getBytes());
    }
}
