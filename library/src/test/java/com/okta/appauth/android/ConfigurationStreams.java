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
            "  \"scopes\": [" +
            "  ]," +
            "  \"issuer_uri\": \"https://example.com/issuer\"" +
            "}";

    public static InputStream getInvalidConfiguration() {
        return new ByteArrayInputStream(INVALID_JSON_CONFIG.getBytes());
    }
}
