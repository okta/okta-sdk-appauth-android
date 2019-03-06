/*
 * Copyright (c) 2018, Okta, Inc. and/or its affiliates. All rights reserved.
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

import android.os.Build;
import android.util.Log;

import java.net.HttpURLConnection;

import javax.net.ssl.HttpsURLConnection;

/**
 * TlsProvider class helper which set {@link TlsEnableSocketFactory} if conditions matched.
 */
public class TlsProvider {

    private static final String TAG = "TlsProvider";

    /**
     * checking current version of Android and set set {@link TlsEnableSocketFactory} if < 20.
     *
     * @param urlConnection object of {@link HttpURLConnection}
     */
    public static void enableIfNeeded(HttpURLConnection urlConnection) {
        if ( urlConnection instanceof HttpsURLConnection &&
                Build.VERSION.SDK_INT <= Build.VERSION_CODES.LOLLIPOP ) {
            try {
                ((HttpsURLConnection)urlConnection)
                        .setSSLSocketFactory(new TlsEnableSocketFactory());
            } catch (Exception e) {
                Log.e(TAG, Log.getStackTraceString(e));
            }
        }
    }
}
