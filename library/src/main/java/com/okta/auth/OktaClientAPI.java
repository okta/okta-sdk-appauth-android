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
import android.support.annotation.WorkerThread;

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
public class OktaClientAPI {

    private OktaAuthAccount mOktaAuthAccount;
    private final MainThreadExecutor mMainThread = new MainThreadExecutor();
    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();

    OktaClientAPI(OktaAuthAccount account) {
        mOktaAuthAccount = account;
    }

    @WorkerThread
    public JSONObject getUserProfile() throws IOException, JSONException {
        HttpResponse response = new HttpRequest.Builder().setRequestMethod(HttpRequest.RequestMethod.POST)
                .setUri(mOktaAuthAccount.getServiceConfig().discoveryDoc.getUserinfoEndpoint())
                .setRequestProperty("Authorization", "Bearer " + mOktaAuthAccount.mTokenResponse.accessToken)
                .create()
                .executeRequest();
        return response.asJson();
    }

    @AnyThread
    public void getUserProfile(@NonNull final RequestCallback<JSONObject, AuthorizationException> cb) {
        performAuthorizedRequest(mOktaAuthAccount.getServiceConfig().discoveryDoc.getUserinfoEndpoint(), cb,
                null, null, HttpRequest.RequestMethod.POST);
    }

    public void performAuthorizedRequest(@NonNull Uri uri, @NonNull final RequestCallback<JSONObject, AuthorizationException> cb,
                                         @Nullable Map<String, String> properties, @Nullable Map<String, String> postParameters,
                                         @NonNull HttpRequest.RequestMethod method) {
        mExecutor.submit(() -> {
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
                        .setRequestProperty("Authorization", "Bearer " + mOktaAuthAccount.mTokenResponse.accessToken)
                        .create()
                        .executeRequest();
                final JSONObject result = response.asJson();
                mMainThread.execute(() -> cb.onSuccess(result));
            } catch (IOException io) {
                AuthorizationException e = AuthorizationException.fromTemplate(
                        AuthorizationException.GeneralErrors.NETWORK_ERROR, io);
                mMainThread.execute(() -> cb.onError("", e));
            } catch (JSONException je) {
                AuthorizationException e = AuthorizationException.fromTemplate(
                        AuthorizationException.GeneralErrors.JSON_DESERIALIZATION_ERROR, je);
                mMainThread.execute(() -> cb.onError("", e));
            }
        });
    }

    @AnyThread
    void stop() {
        mMainThread.shutdown();
        mExecutor.shutdownNow();
    }
}