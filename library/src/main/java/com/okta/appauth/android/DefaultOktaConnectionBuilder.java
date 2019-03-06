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

import android.net.Uri;
import android.support.annotation.NonNull;

import net.openid.appauth.Preconditions;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.TimeUnit;

/**
 * This is ConnectionBuilder which provides to AppAuth library and enable TLS v1.2 for < API 20.
 */
public class DefaultOktaConnectionBuilder implements OktaConnectionBuilder {
    /**
     * The singleton instance of the Okta default connection builder.
     */
    public static final DefaultOktaConnectionBuilder INSTANCE = new DefaultOktaConnectionBuilder();

    private static final int CONNECTION_TIMEOUT_MS = (int) TimeUnit.SECONDS.toMillis(15);
    private static final int READ_TIMEOUT_MS = (int) TimeUnit.SECONDS.toMillis(10);

    private static final String HTTPS_SCHEME = "https";

    private DefaultOktaConnectionBuilder() {
        // no need to construct instances of this type
    }

    @NonNull
    @Override
    public HttpURLConnection openConnection(@NonNull Uri uri) throws IOException {
        Preconditions.checkNotNull(uri, "url must not be null");
        Preconditions.checkArgument(HTTPS_SCHEME.equals(uri.getScheme()),
                "only https connections are permitted");
        HttpURLConnection conn = (HttpURLConnection) new URL(uri.toString()).openConnection();
        TlsProvider.enableIfNeeded(conn);
        conn.setConnectTimeout(CONNECTION_TIMEOUT_MS);
        conn.setReadTimeout(READ_TIMEOUT_MS);
        conn.setInstanceFollowRedirects(false);
        return conn;
    }
}
