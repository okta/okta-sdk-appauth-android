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
import android.support.annotation.Nullable;
import android.text.TextUtils;

import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationRequest;
import net.openid.appauth.AuthorizationResponse;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.ClientAuthentication;
import net.openid.appauth.TokenResponse;
import net.openid.appauth.connectivity.ConnectionBuilder;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

class SessionAuthenticationService {
    private static final String SESSION_TOKEN_PARAMETER = "sessionToken";

    private AuthStateManager mStateManager;
    private AuthorizationService mAuthService;
    private ConnectionBuilder mConnectionBuilder;

    SessionAuthenticationService(
            AuthStateManager manager,
            AuthorizationService authorizationService,
            ConnectionBuilder connectionBuilder) {
        mStateManager = manager;
        mAuthService = authorizationService;
        mConnectionBuilder = connectionBuilder;
    }

    void performAuthorizationRequest(
            AuthorizationRequest request,
            String sessionToken,
            @Nullable OktaAppAuth.OktaNativeAuthListener listener) {
        if (sessionToken == null) {
            if (listener != null) {
                listener.onTokenFailure(AuthenticationError.createAuthenticationError(
                        AuthenticationError.INVALID_SESSION_TOKEN,
                        0));
            }

            return;
        }

        Map<String, String> additionalParameters = new HashMap<String, String>();
        if (request.additionalParameters != null && !request.additionalParameters.isEmpty()) {
            additionalParameters.putAll(request.additionalParameters);
        }
        additionalParameters.put(SESSION_TOKEN_PARAMETER, sessionToken);

        AuthorizationRequest.Builder authRequestBuilder = new AuthorizationRequest.Builder(
                request.configuration,
                request.clientId,
                request.responseType,
                request.redirectUri)
                .setNonce(request.nonce)
                .setScopes(request.getScopeSet())
                .setAdditionalParameters(additionalParameters);

        AuthenticationResult<AuthorizationResponse> authorizationResult = getAuthorizationCode(
                authRequestBuilder.build());
        if (authorizationResult.getResponse() == null ||
                authorizationResult.getResponse().authorizationCode == null) {
            if (listener != null) {
                listener.onTokenFailure(authorizationResult.getException());
            }
            return;
        }

        AuthenticationResult<TokenResponse> tokenResponse = exchangeCodeForTokens(
                authorizationResult.getResponse());
        if (!mStateManager.getCurrent().isAuthorized()) {
            if (listener != null) {
                listener.onTokenFailure(tokenResponse.getException());
            }
        } else {
            if (listener != null) {
                listener.onSuccess();
            }
        }
    }

    @NonNull
    private AuthenticationResult<AuthorizationResponse> getAuthorizationCode(
            final AuthorizationRequest request) {
        HttpURLConnection conn = null;
        try {
            conn = mConnectionBuilder.openConnection(request.toUri());
            conn.setInstanceFollowRedirects(false);


            if (conn.getResponseCode() != HttpURLConnection.HTTP_MOVED_TEMP ||
                    (conn.getHeaderField("Location") == null ||
                            conn.getHeaderField("Location").length() == 0)) {
                AuthenticationError error = AuthenticationError.createAuthenticationError(
                        AuthenticationError.INVALID_AUTHORIZE_REQUEST, conn.getResponseCode());
                mStateManager.updateAfterAuthorization(
                        null,
                        AuthorizationException.AuthorizationRequestErrors.byString(
                                error.getMessage()));
                return new AuthenticationResult<AuthorizationResponse>(null, error);
            }

            Uri locationUri = Uri.parse(conn.getHeaderField("Location"));
            String code = locationUri.getQueryParameter("code");
            String state = locationUri.getQueryParameter("state");
            if (TextUtils.isEmpty(code) || TextUtils.isEmpty(state)) {
                String error = locationUri.getQueryParameter("error");
                String errorDescription = locationUri.getQueryParameter("error_description");
                mStateManager.updateAfterAuthorization(
                        null,
                        AuthorizationException.AuthorizationRequestErrors.byString(
                                errorDescription));
                return new AuthenticationResult<AuthorizationResponse>(
                        null,
                        new AuthenticationError(
                                error, conn.getResponseCode(), errorDescription));
            }

            AuthorizationResponse authorizationResponse = new AuthorizationResponse.Builder(request)
                    .setAuthorizationCode(code)
                    .setState(state)
                    .build();

            return new AuthenticationResult<AuthorizationResponse>(
                    authorizationResponse, null);
        } catch (MalformedURLException ex) {
            ex.printStackTrace();
            mStateManager.updateAfterAuthorization(
                    null,
                    AuthorizationException.AuthorizationRequestErrors.byString(ex.getMessage()));
            return new AuthenticationResult<AuthorizationResponse>(
                    null, AuthenticationError.createAuthenticationError(ex));
        } catch (IOException ex) {
            ex.printStackTrace();
            mStateManager.updateAfterAuthorization(
                    null,
                    AuthorizationException.AuthorizationRequestErrors.byString(ex.getMessage()));
            return new AuthenticationResult<AuthorizationResponse>(
                    null,
                    AuthenticationError.createAuthenticationError(ex));
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    @NonNull
    private AuthenticationResult<TokenResponse> exchangeCodeForTokens(
            final AuthorizationResponse authorizationResponse) {
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final AtomicReference<AuthenticationResult> result =
                new AtomicReference<AuthenticationResult>(null);

        try {
            ClientAuthentication clientAuthentication = mStateManager.getCurrent()
                    .getClientAuthentication();
            mAuthService.performTokenRequest(
                    authorizationResponse.createTokenExchangeRequest(),
                    clientAuthentication,
                    new AuthorizationService.TokenResponseCallback() {
                        @Override
                        public void onTokenRequestCompleted(@Nullable TokenResponse response,
                                                            @Nullable AuthorizationException ex) {
                            mStateManager.updateAfterTokenResponse(response, ex);
                            AuthenticationResult<TokenResponse> authenticationResult =
                                    new AuthenticationResult<TokenResponse>(
                                            response,
                                            (ex != null ?
                                                    AuthenticationError
                                                            .createAuthenticationError(ex) : null));
                            result.compareAndSet(null, authenticationResult);
                            countDownLatch.countDown();
                        }
                    });
            countDownLatch.await();
            return result.get();
        } catch (ClientAuthentication.UnsupportedAuthenticationMethod ex) {
            mStateManager.updateAfterTokenResponse(
                    null,
                    AuthorizationException.TokenRequestErrors.byString(ex.getMessage()));
            return new AuthenticationResult<TokenResponse>(
                    null, AuthenticationError.createAuthenticationError(ex));
        } catch (InterruptedException ex) {
            mStateManager.updateAfterTokenResponse(
                    null,
                    AuthorizationException.TokenRequestErrors.byString(ex.getMessage()));
            return new AuthenticationResult<TokenResponse>(
                    null, AuthenticationError.createAuthenticationError(ex));
        }
    }

    private static class AuthenticationResult<T> {
        private T mResponse;
        private AuthenticationError mException;

        AuthenticationResult(T response, AuthenticationError exception) {
            this.mResponse = response;
            this.mException = exception;
        }

        T getResponse() {
            return mResponse;
        }

        AuthenticationError getException() {
            return mException;
        }
    }
}

