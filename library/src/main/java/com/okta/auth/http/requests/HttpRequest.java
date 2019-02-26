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
import com.okta.openid.appauth.AuthorizationException;

import java.util.concurrent.ExecutorService;

public interface HttpRequest<T, U extends AuthorizationException> {
    public enum Type {
        CONFIGURATION,
        TOKEN_EXCHANGE,
        AUTHORIZED,
        PROFILE
    }

    void dispatchRequest(ExecutorService dispatcher, RequestCallback<T, U> callback);

    T executeRequest() throws AuthorizationException;

    void cancelRequest();

    void close();
}
