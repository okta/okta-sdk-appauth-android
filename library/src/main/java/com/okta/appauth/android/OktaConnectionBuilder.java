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

import java.io.IOException;
import java.net.HttpURLConnection;

/**
 * Creates {@link java.net.HttpURLConnection} instances for use in direct interactions
 * with the authorization service, i.e. those not performed via a browser.
 * This interface is similar to Connection Builder in app
 * {@link net.openid.appauth.connectivity.ConnectionBuilder}.
 * In future net.openid.appauth package will be removed and we don't need to provide any classes
 * from this package for client
 */
public interface OktaConnectionBuilder {
    /**
     * Creates a connection to the specified URL.
     * @param uri - Uri
     * @throws IOException if an error occurs while attempting to establish the connection.
     * @return HttpURLConnection
     */
    @NonNull
    HttpURLConnection openConnection(@NonNull Uri uri) throws IOException;
}
