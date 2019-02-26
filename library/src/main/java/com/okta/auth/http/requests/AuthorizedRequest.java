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

import com.okta.auth.RequestCallback;
import com.okta.auth.http.HttpConnection;
import com.okta.auth.http.HttpResponse;
import com.okta.openid.appauth.AuthorizationException;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.concurrent.ExecutorService;

public class AuthorizedRequest extends BaseRequest<JSONObject, AuthorizationException> {
    AuthorizedRequest(HttpRequestBuilder b) {
        super();
        mRequestType = b.mRequestType;
        mUri = b.mUri;
        HttpConnection.Builder builder = new HttpConnection.Builder();
        if (b.mPostParameters != null) {
            builder.setPostParameters(b.mPostParameters);
        }
        if (b.mProperties != null) {
            builder.setRequestProperties(b.mProperties);
        }
        mConnection = builder
                .setRequestMethod(b.mRequestMethod)
                .setRequestProperty("Authorization", "Bearer " + b.mAccount.getAccessToken())
                .setRequestProperty("Accept", HttpConnection.JSON_CONTENT_TYPE)
                .create(b.mConn);
    }

    @Override
    public void dispatchRequest(ExecutorService dispatcher, RequestCallback<JSONObject, AuthorizationException> callback) {
        dispatcher.submit(() -> {
            try {
                callback.onSuccess(executeRequest());
            } catch (AuthorizationException ae) {
                callback.onError(ae.errorDescription, ae);
            }
        });
    }

    @Override
    public JSONObject executeRequest() throws AuthorizationException {
        AuthorizationException exception = null;
        HttpResponse response = null;
        try {
            response = openConnection();
            return response.asJson();
        } catch (IOException io) {
            exception = AuthorizationException.fromTemplate(
                    AuthorizationException.GeneralErrors.NETWORK_ERROR, io);
        } catch (JSONException je) {
            exception = AuthorizationException.fromTemplate(
                    AuthorizationException.GeneralErrors.JSON_DESERIALIZATION_ERROR, je);
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
