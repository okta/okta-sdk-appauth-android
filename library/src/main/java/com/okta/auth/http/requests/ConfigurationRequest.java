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
import android.support.annotation.WorkerThread;

import com.okta.auth.RequestCallback;
import com.okta.auth.http.HttpConnection;
import com.okta.auth.http.HttpResponse;
import com.okta.openid.appauth.AuthorizationException;
import com.okta.openid.appauth.AuthorizationServiceDiscovery;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.concurrent.ExecutorService;

import static android.support.annotation.RestrictTo.Scope.LIBRARY_GROUP;

@RestrictTo(LIBRARY_GROUP)
public final class ConfigurationRequest extends BaseRequest<AuthorizationServiceDiscovery, AuthorizationException> {
    ConfigurationRequest(HttpRequestBuilder b) {
        super();
        mRequestType = b.mRequestType;
        mUri = b.mAccount.getDiscoveryUri();
        mConnection = new HttpConnection.Builder()
                .setRequestMethod(HttpConnection.RequestMethod.GET)
                .create(b.mConn);
    }

    @Override
    public void dispatchRequest(ExecutorService dispatcher, final RequestCallback<AuthorizationServiceDiscovery, AuthorizationException> callback) {
        dispatcher.submit(() -> {
            try {
                AuthorizationServiceDiscovery serviceDiscovery = executeRequest();
                if (serviceDiscovery != null) {
                    callback.onSuccess(serviceDiscovery);
                } else {
                    throw AuthorizationException.GeneralErrors.INVALID_DISCOVERY_DOCUMENT;
                }
            } catch (AuthorizationException ae) {
                callback.onError(ae.errorDescription, ae);
            }
        });
    }

    @WorkerThread
    @Override
    public AuthorizationServiceDiscovery executeRequest() throws AuthorizationException {
        AuthorizationException exception = null;
        HttpResponse response = null;
        try {
            response = openConnection();
            JSONObject json = response.asJson();
            return new AuthorizationServiceDiscovery(json);
        } catch (IOException ex) {
            exception = AuthorizationException.fromTemplate(
                    AuthorizationException.GeneralErrors.NETWORK_ERROR,
                    ex);
        } catch (JSONException ex) {
            exception = AuthorizationException.fromTemplate(
                    AuthorizationException.GeneralErrors.JSON_DESERIALIZATION_ERROR,
                    ex);
        } catch (AuthorizationServiceDiscovery.MissingArgumentException ex) {
            exception = AuthorizationException.fromTemplate(
                    AuthorizationException.GeneralErrors.INVALID_DISCOVERY_DOCUMENT,
                    ex);
        } finally {
            if (response != null) {
                response.disconnect();
            }
            if (exception != null) {
                throw exception;
            }
        }
        return null;
    }
}