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

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.VisibleForTesting;
import android.support.annotation.WorkerThread;
import android.util.Log;
import net.openid.appauth.AuthorizationException;
import okio.ByteString;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * Insulates logic for building and performing Revocation request.
 *
 * @see "OAuth 2.0 Token Revocation <https://tools.ietf.org/html/rfc7009>"
 *
 */
class RevokeTokenRequest {

    private static final String TOKEN_PARAM = "token";
    private static final String CLIENT_ID_PARAM = "client_id";

    private static final int OK_RESPONSE_CODE = 200;
    private static final int UNAUTHORIZED_ERROR_CODE = 401;

    @VisibleForTesting
    static final String REVOKE_ENDPOINT_KEY = "revocation_endpoint";
    private static final String TAG = RevokeTokenRequest.class.getSimpleName();

    /**
     * Revocation URL.
     */
    private URL mRevokeUrl;

    private RevokeTokenRequest(URL revokeRequest) {
        this.mRevokeUrl = revokeRequest;
    }

    static class Builder {

        private String mToken;
        private String mClientId;
        private JSONObject mServiceConfig;

        /**
         * creates a Builder for revoke request.
         *
         * @param serviceConfig - service config
         */
        Builder(JSONObject serviceConfig) {
            this.mServiceConfig = serviceConfig;
        }

        /**
         * adds accessToken or refreshToken for revocation.
         */
        Builder addToken(String token) {
            this.mToken = token;
            return this;
        }

        /**
         * adds okta client id.
         */
        Builder addClientId(String clientId) {
            this.mClientId = clientId;
            return this;
        }

        /**
         * builds revocation request.
         */
        @Nullable
        RevokeTokenRequest build() {

            StringBuilder resultUrlBuilder;
            try {
                resultUrlBuilder = new StringBuilder(mServiceConfig.getString(REVOKE_ENDPOINT_KEY));
            } catch (JSONException e) {
                Log.e(TAG, "build: ", e);
                return null;
            }
            resultUrlBuilder.append("?");
            resultUrlBuilder.append(TOKEN_PARAM);
            resultUrlBuilder.append("=");
            resultUrlBuilder.append(mToken);
            resultUrlBuilder.append("&");
            resultUrlBuilder.append(CLIENT_ID_PARAM);
            resultUrlBuilder.append("=");
            resultUrlBuilder.append(mClientId);

            URL url;
            try {
                url = new URL(ByteString.encodeUtf8(resultUrlBuilder.toString()).utf8());
            } catch (MalformedURLException e) {
                Log.e(TAG, "build: ", e);
                return null;
            }

            return new RevokeTokenRequest(url);

        }

    }

    /**
     * synchronously performs revocation request.
     */
    @WorkerThread
    void performRequest(@NonNull RevokeListener callback) {

        try {
            HttpURLConnection urlConnection = (HttpURLConnection) mRevokeUrl.openConnection();
            urlConnection.setDoOutput(true);
            urlConnection.setInstanceFollowRedirects(false);
            urlConnection.setChunkedStreamingMode(0);
            urlConnection.setRequestProperty("Accept", "application/json");
            urlConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

            urlConnection.setRequestMethod("POST");
            urlConnection.connect();
            int responseCode = urlConnection.getResponseCode();
            if (responseCode == OK_RESPONSE_CODE) {
                callback.onSuccess();
            } else if (responseCode == UNAUTHORIZED_ERROR_CODE) {
                callback.onError(AuthorizationException.TokenRequestErrors.INVALID_CLIENT);
            } else {
                callback.onError(AuthorizationException.TokenRequestErrors.OTHER);
            }

            Log.d(TAG, "performRequest: responseCode " + urlConnection.getResponseCode());
        } catch (IOException e) {
            Log.e(TAG, "performRequest: ", e);
            callback.onError(AuthorizationException.TokenRequestErrors.INVALID_REQUEST);
        }
    }

    /**
     * Notifies on revocation results.
     */
    interface RevokeListener {

        /**
         * Called when the operation is successful to allow the caller to be notified.
         */
        void onSuccess();


        /**
         * Called when a failure occurs during the operation related to the revocation flow.
         *
         * @param ex The exception describing the failure
         */
        void onError(AuthorizationException ex);

    }
}
