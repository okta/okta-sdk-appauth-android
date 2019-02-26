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
import android.support.annotation.Nullable;
import android.support.annotation.RawRes;
import android.util.Log;

import com.okta.android.json.InvalidJsonDocumentException;
import com.okta.android.json.JsonParser;
import com.okta.openid.appauth.AuthorizationServiceConfiguration;
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
    Okta OIDC application information
 */
public class OIDCAccount {
    private static final String TAG = OIDCAccount.class.getSimpleName();
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

    private TokenResponse mTokenResponse;

    private static final String OIDC_DISCOVERY = ".well-known/openid-configuration";

    private AuthorizationServiceConfiguration mServiceConfig;

    private OIDCAccount(Builder builder) {
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
        if (mServiceConfig != null) {
            editor.putString(OIDC_DISCOVERY, mServiceConfig.toJsonString());
        }
    }

    void restore(SharedPreferences prefs) throws JSONException {
        mClientId = prefs.getString(CLIENT_ID, null);
        mRedirectUri = Uri.parse(prefs.getString(REDIRECT_URI, null));
        mEndSessionRedirectUri = Uri.parse(prefs.getString(END_SESSION_REDIRECT_URI, null));
        mDiscoveryUri = Uri.parse(prefs.getString(DISCOVERY_URI, null));
        String json = prefs.getString(OIDC_DISCOVERY, null);
        if (json != null) {
            mServiceConfig = AuthorizationServiceConfiguration.fromJson(json);
        }
    }

    public void setTokenResponse(TokenResponse token) {
        mTokenResponse = token;
    }

    public boolean haveServiceConfig() {
        return mServiceConfig != null;
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

    public Uri getDiscoveryUri() {
        return mDiscoveryUri.buildUpon().appendEncodedPath(OIDC_DISCOVERY).build();
    }

    public Set<String> getScopes() {
        return mScopes;
    }

    boolean haveConfiguration() {
        return mServiceConfig != null;
    }

    public AuthorizationServiceConfiguration getServiceConfig() {
        return mServiceConfig;
    }

    void setServiceConfig(AuthorizationServiceConfiguration config) {
        mServiceConfig = config;
    }

    public boolean isLoggedIn() {
        return mTokenResponse != null && (mTokenResponse.accessToken != null || mTokenResponse.idToken != null);
    }

    public @Nullable
    String getAccessToken() {
        return mTokenResponse.accessToken;
    }

    public @Nullable
    String getIdToken() {
        return mTokenResponse.idToken;
    }

    public @Nullable
    String getRefreshToken() {
        return mTokenResponse.refreshToken;
    }

    public static class Builder {
        private String mClientId;
        private Uri mRedirectUri;
        private Uri mEndSessionRedirectUri;
        private Uri mDiscoveryUri;
        private Set<String> mScopes;

        public Builder() {
        }

        public OIDCAccount create() {
            return new OIDCAccount(this);
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