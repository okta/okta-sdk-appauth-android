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

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.support.annotation.NonNull;
import android.support.annotation.RawRes;
import android.support.annotation.WorkerThread;
import android.util.Log;

import com.okta.android.json.InvalidJsonDocumentException;
import com.okta.android.json.JsonParser;
import com.okta.auth.http.HttpRequest;
import com.okta.auth.http.HttpResponse;
import com.okta.openid.appauth.AuthorizationException;
import com.okta.openid.appauth.AuthorizationServiceConfiguration;
import com.okta.openid.appauth.AuthorizationServiceDiscovery;
import com.okta.openid.appauth.TokenResponse;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.io.Writer;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/*
    Okta OID application information
 */
public class OktaAuthAccount {
    private static final String TAG = OktaAuthAccount.class.getSimpleName();
    private static final String TOKEN_RESPONSE = "token_response";
    private static final String CLIENT_ID = "client_id";
    private static final String REDIRECT_URI = "redirect_uri";
    private static final String END_SESSION_REDIRECT_URI = "end_session_redirect_uri";
    private static final String DISCOVERY_URI = "issuer_uri";
    private static final String SCOPES = "scopes";

    private String mClientId;
    private Uri mRedirectUri;
    private Uri mEndSessionRedirectUri;
    private Uri mDiscoveryUri;
    private Set<String> mScopes;

    OktaAuthManager.LoginMethod mLoginMethod;
    TokenResponse mTokenResponse;

    private static final String OIDC_DISCOVERY = ".well-known/openid-configuration";

    private AuthorizationServiceConfiguration mServiceConfig;

    private OktaAuthAccount(Builder builder) {
        mClientId = builder.mClientId;
        mRedirectUri = builder.mRedirectUri;
        mEndSessionRedirectUri = builder.mEndSessionRedirectUri;
        mDiscoveryUri = builder.mDiscoveryUri;
        mScopes = builder.mScopes;
    }

    void persist(SharedPreferences.Editor editor) {
        editor.putString(CLIENT_ID, mClientId);
        editor.putString(REDIRECT_URI, mRedirectUri.toString());
        editor.putString(END_SESSION_REDIRECT_URI, mEndSessionRedirectUri.toString());
        editor.putString(DISCOVERY_URI, mDiscoveryUri.toString());
        if (mTokenResponse != null) {
            editor.putString(TOKEN_RESPONSE, mTokenResponse.jsonSerializeString());
        }
        editor.putString(OIDC_DISCOVERY, mServiceConfig.toJsonString());
    }

    void restore(SharedPreferences prefs) throws JSONException {
        mClientId = prefs.getString(CLIENT_ID, null);
        mRedirectUri = Uri.parse(prefs.getString(REDIRECT_URI, null));
        mEndSessionRedirectUri = Uri.parse(prefs.getString(END_SESSION_REDIRECT_URI, null));
        mDiscoveryUri = Uri.parse(prefs.getString(DISCOVERY_URI, null));
        mTokenResponse = TokenResponse.jsonDeserialize(prefs.getString(TOKEN_RESPONSE, null));
        mServiceConfig = AuthorizationServiceConfiguration.fromJson(prefs.getString(OIDC_DISCOVERY, null));
    }

    public String getClientId() {
        return mClientId;
    }

    public Uri getRedirectUri() {
        return mRedirectUri;
    }

    public Uri getEndSessionRedirectUri() {
        return mEndSessionRedirectUri;
    }

    private Uri getDiscoveryUri() {
        return mDiscoveryUri.buildUpon().appendEncodedPath(OIDC_DISCOVERY).build();
    }

    public Set<String> getScopes() {
        return mScopes;
    }

    boolean haveConfiguration() {
        return mServiceConfig != null;
    }

    AuthorizationServiceConfiguration getServiceConfig() {
        return mServiceConfig;
    }


    public boolean isLoggedIn() {
        return mTokenResponse != null && (mTokenResponse.accessToken != null || mTokenResponse.idToken != null);
    }

    @WorkerThread
    void obtainConfiguration() throws AuthorizationException {
        AuthorizationException exception = null;
        HttpResponse response = null;
        try {
            response = new HttpRequest.Builder().setRequestMethod(HttpRequest.RequestMethod.GET)
                    .setUri(getDiscoveryUri())
                    .create()
                    .executeRequest();
            JSONObject json = response.asJson();
            AuthorizationServiceDiscovery discovery =
                    new AuthorizationServiceDiscovery(json);
            mServiceConfig = new AuthorizationServiceConfiguration(discovery);
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
                mServiceConfig = null;
                throw exception;
            }
        }
    }

    public static class Builder {
        private String mClientId;
        private Uri mRedirectUri;
        private Uri mEndSessionRedirectUri;
        private Uri mDiscoveryUri;
        private Set<String> mScopes;

        public Builder() {
        }

        public OktaAuthAccount create() {
            return new OktaAuthAccount(this);
        }

        public Builder clientId(@NonNull String clientId) {
            mClientId = clientId;
            return this;
        }

        public Builder redirectUri(@NonNull String redirect) {
            mRedirectUri = Uri.parse(redirect);
            return this;
        }

        public Builder endSessionRedirectUri(@NonNull String endSessionRedirect) {
            mEndSessionRedirectUri = Uri.parse(endSessionRedirect);
            return this;
        }

        public Builder discoveryUri(@NonNull String discoveryUri) {
            mDiscoveryUri = Uri.parse(discoveryUri);
            return this;
        }

        public Builder scopes(@NonNull String... scopes) {
            mScopes = new LinkedHashSet<>(scopes.length);
            Collections.addAll(mScopes, scopes);
            return this;
        }

        public Builder withResId(Context context, @RawRes int Id) {
            try (InputStream inputStream = context.getResources().openRawResource(Id)) {
                Writer writer = new StringWriter();
                BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, "UTF-8"));
                String line = reader.readLine();
                while (line != null) {
                    writer.write(line);
                    line = reader.readLine();
                }
                JSONObject json = new JSONObject(writer.toString());
                readConfiguration(json);
            } catch (IOException e) {
                Log.e(TAG, "", e);
                return null;
            } catch (JSONException e) {
                Log.e(TAG, "", e);
                return null;
            } catch (InvalidJsonDocumentException e) {
                Log.e(TAG, "", e);
                return null;
            }
            return this;
        }

        private void readConfiguration(@NonNull final JSONObject jsonObject)
                throws InvalidJsonDocumentException {
            JsonParser jsonParser = JsonParser.forJson(jsonObject);
            mClientId = jsonParser.getRequiredString(CLIENT_ID);
            mRedirectUri = jsonParser.getRequiredUri(REDIRECT_URI);
            mEndSessionRedirectUri = jsonParser.getRequiredUri(END_SESSION_REDIRECT_URI);
            mDiscoveryUri = jsonParser.getRequiredHttpsUri(DISCOVERY_URI)
                    .buildUpon().appendEncodedPath(OIDC_DISCOVERY).build();

            mScopes = new LinkedHashSet<>(jsonParser.getRequiredStringArray(SCOPES));
        }
    }
}