/*
 * Copyright (c) 2019, Okta, Inc. and/or its affiliates. All rights reserved.
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
package com.okta.auth.http.requests;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.RestrictTo;

import com.okta.auth.RequestCallback;
import com.okta.auth.ThreadDispatcher;
import com.okta.auth.http.HttpConnection;
import com.okta.auth.http.HttpResponse;
import com.okta.openid.appauth.AuthorizationException;
import com.okta.openid.appauth.AuthorizationRequest;
import com.okta.openid.appauth.IdToken;
import com.okta.openid.appauth.SystemClock;
import com.okta.openid.appauth.TokenRequest;
import com.okta.openid.appauth.TokenResponse;
import com.okta.openid.appauth.internal.UriUtil;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ExecutorService;

import static android.support.annotation.RestrictTo.Scope.LIBRARY_GROUP;

@RestrictTo(LIBRARY_GROUP)
public class TokenExchangeRequest extends BaseRequest<TokenResponse, AuthorizationException> {
    private TokenRequest mTokenRequest;

    TokenExchangeRequest(HttpRequestBuilder b) {
        super();
        mRequestType = b.mRequestType;
        mUri = b.mAccount.getServiceConfig().tokenEndpoint;
        mTokenRequest = b.mAuthResponse.createTokenExchangeRequest();
        Map<String, String> parameters = mTokenRequest.getRequestParameters();
        parameters.put(TokenRequest.PARAM_CLIENT_ID, ((AuthorizationRequest) b.mAuthRequest).clientId);
        mConnection = new HttpConnection.Builder()
                .setRequestMethod(HttpConnection.RequestMethod.POST)
                .setRequestProperty("Accept", HttpConnection.JSON_CONTENT_TYPE)
                .setPostParameters(parameters)
                .create(b.mConn);
    }

    @Override
    public void dispatchRequest(ExecutorService dispatcher, final RequestCallback<TokenResponse, AuthorizationException> callback) {
        dispatcher.submit(() -> {
            try {
                callback.onSuccess(executeRequest());
            } catch (AuthorizationException ae) {
                callback.onError(ae.errorDescription, ae);
            }
        });
    }

    @Override
    public TokenResponse executeRequest() throws AuthorizationException {
        HttpResponse response = null;
        TokenResponse tokenResponse;
        try {
            response = openConnection();
            JSONObject json = response.asJson();
            if (json.has(AuthorizationException.PARAM_ERROR)) {
                try {
                    final String error = json.getString(AuthorizationException.PARAM_ERROR);
                    throw AuthorizationException.fromOAuthTemplate(
                            AuthorizationException.TokenRequestErrors.byString(error),
                            error,
                            json.optString(AuthorizationException.PARAM_ERROR_DESCRIPTION, null),
                            UriUtil.parseUriIfAvailable(
                                    json.optString(AuthorizationException.PARAM_ERROR_URI)));
                } catch (JSONException jsonEx) {
                    throw AuthorizationException.fromTemplate(
                            AuthorizationException.GeneralErrors.JSON_DESERIALIZATION_ERROR,
                            jsonEx);
                }
            }

            try {
                tokenResponse = new TokenResponse.Builder(mTokenRequest).fromResponseJson(json).build();
            } catch (JSONException jsonEx) {
                throw AuthorizationException.fromTemplate(
                        AuthorizationException.GeneralErrors.JSON_DESERIALIZATION_ERROR,
                        jsonEx);
            }

            if (tokenResponse.idToken != null) {
                IdToken idToken;
                try {
                    idToken = IdToken.from(tokenResponse.idToken);
                } catch (IdToken.IdTokenException | JSONException ex) {
                    throw AuthorizationException.fromTemplate(
                            AuthorizationException.GeneralErrors.ID_TOKEN_PARSING_ERROR,
                            ex);
                }
                idToken.validate(mTokenRequest, SystemClock.INSTANCE);
            }
            return tokenResponse;
        } catch (IOException ex) {
            throw AuthorizationException.fromTemplate(
                    AuthorizationException.GeneralErrors.NETWORK_ERROR, ex);
        } catch (JSONException ex) {
            throw AuthorizationException.fromTemplate(
                    AuthorizationException.GeneralErrors.JSON_DESERIALIZATION_ERROR, ex);
        } finally {
            if (response != null) {
                response.disconnect();
            }
        }
    }
}
