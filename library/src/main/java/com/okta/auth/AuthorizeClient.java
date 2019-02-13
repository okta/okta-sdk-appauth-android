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
package com.okta.auth;

import android.net.Uri;
import android.support.annotation.AnyThread;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.okta.auth.http.HttpRequest;
import com.okta.auth.http.HttpResponse;
import com.okta.openid.appauth.AuthorizationException;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

//Client API for a client that is already logged in (authenticated).
public class AuthorizeClient {
    private AuthorizeAPI mAuthorizeAPI;
    private final MainThreadExecutor mMainThread = new MainThreadExecutor();
    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();

    private interface Request {
        JSONObject startRequest() throws AuthorizationException;
    }

    AuthorizeClient(@NonNull AuthAccount account) {
        mAuthorizeAPI = new AuthorizeAPI(account);
    }

    public AuthorizeAPI getClientApi() {
        return mAuthorizeAPI;
    }

    @AnyThread
    public void getUserProfile(@NonNull final RequestCallback<JSONObject, AuthorizationException> cb) {
        performRequest(() -> mAuthorizeAPI.getUserProfile(), cb);
    }

    @AnyThread
    public void performAuthorizedRequest(@NonNull final Uri uri, @NonNull final RequestCallback<JSONObject, AuthorizationException> cb,
                                         @Nullable final Map<String, String> properties, @Nullable final Map<String, String> postParameters,
                                         @NonNull final HttpRequest.RequestMethod method) {
        performRequest(() -> mAuthorizeAPI.performAuthorizedRequest(uri, properties, postParameters, method), cb);
    }

    private void performRequest(Request request, RequestCallback<JSONObject, AuthorizationException> cb) {
        mExecutor.submit(() -> {
            try {
                final JSONObject result = request.startRequest();
                mMainThread.execute(() -> cb.onSuccess(result));
            } catch (AuthorizationException ae) {
                mMainThread.execute(() -> cb.onError("", ae));
            }
        });
    }

    @AnyThread
    void stop() {
        mMainThread.shutdown();
        mExecutor.shutdownNow();
    }

    public final class AuthorizeAPI {
        private AuthAccount mAuthAccount;

        AuthorizeAPI(AuthAccount account) {
            mAuthAccount = account;
        }

        public @Nullable
        JSONObject getUserProfile() throws AuthorizationException {
            return performAuthorizedRequest(mAuthAccount.getServiceConfig().discoveryDoc.getUserinfoEndpoint(),
                    null, null, HttpRequest.RequestMethod.POST);
        }

        public @Nullable
        JSONObject performAuthorizedRequest(@NonNull Uri uri,
                                            @Nullable Map<String, String> properties, @Nullable Map<String, String> postParameters,
                                            @NonNull HttpRequest.RequestMethod method) throws AuthorizationException {
            AuthorizationException exception = null;
            try {
                HttpRequest.Builder builder = new HttpRequest.Builder();
                if (postParameters != null) {
                    builder.setPostParameters(postParameters);
                }
                if (properties != null) {
                    builder.setRequestProperties(properties);
                }
                HttpResponse response = builder.setRequestMethod(method)
                        .setUri(uri)
                        .setRequestProperty("Authorization", "Bearer " + mAuthAccount.mTokenResponse.accessToken)
                        .create()
                        .executeRequest();
                return response.asJson();
            } catch (IOException io) {
                exception = AuthorizationException.fromTemplate(
                        AuthorizationException.GeneralErrors.NETWORK_ERROR, io);
            } catch (JSONException je) {
                exception = AuthorizationException.fromTemplate(
                        AuthorizationException.GeneralErrors.JSON_DESERIALIZATION_ERROR, je);
            } finally {
                if (exception != null) {
                    throw exception;
                }
            }
            return null;
        }
    }
}