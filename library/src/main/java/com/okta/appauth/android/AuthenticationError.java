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

import net.openid.appauth.AuthorizationException;
import net.openid.appauth.ClientAuthentication;

/**
 * The class which represent errors which happen during authentication.
 */
public class AuthenticationError extends Exception {
    static final  int INVALID_AUTHORIZE_REQUEST = 0;
    static final  int INVALID_SESSION_TOKEN = 1;

    private String mCode;
    private int mStatusCode;


    AuthenticationError(String mCode, int mStatusCode, String message) {
        super(message);
        this.mCode = mCode;
        this.mStatusCode = mStatusCode;
    }

    static AuthenticationError createAuthenticationError(Exception e) {
        return new AuthenticationError(e.getMessage(), e.hashCode(), e.getLocalizedMessage());
    }

    static AuthenticationError createAuthenticationError(
            ClientAuthentication.UnsupportedAuthenticationMethod e) {
        return new AuthenticationError(
                e.getUnsupportedAuthenticationMethod(),
                e.hashCode(),
                e.getLocalizedMessage());
    }

    static AuthenticationError createAuthenticationError(AuthorizationException e) {
        return new AuthenticationError(e.error, e.code, e.errorDescription);
    }

    static AuthenticationError createAuthenticationError(int error, int code) {
        switch (error) {
            case INVALID_AUTHORIZE_REQUEST:
                return new AuthenticationError(
                       "invalid_authorize_request",
                       code,
                       "Expected HTTP mCode status 302 with Location header");
            case INVALID_SESSION_TOKEN:
                return new AuthenticationError(
                        "session_token_couldn't be null",
                        code,
                        "Session Token is null");
            default:
                throw new RuntimeException("Invalid error type value in AuthenticationError");
        }
    }

    /**
     * The current code.
     *
     * @return code.
     */
    public String getCode() {
        return mCode;
    }

    /**
     * The current code.
     *
     * @return statusCode.
     */
    public int getStatusCode() {
        return mStatusCode;
    }
}
