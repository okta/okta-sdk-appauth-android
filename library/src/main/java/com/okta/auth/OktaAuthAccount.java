package com.okta.auth;

import android.content.Context;
import android.net.Uri;
import android.support.annotation.NonNull;
import android.support.annotation.RawRes;
import android.support.annotation.WorkerThread;
import android.util.Log;

import com.okta.android.json.InvalidJsonDocumentException;
import com.okta.android.json.JsonParser;
import com.okta.auth.http.HttpRequest;
import com.okta.auth.http.HttpResponse;

import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationServiceConfiguration;
import net.openid.appauth.AuthorizationServiceDiscovery;

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
    //for parsing okta_app_auth_config.json
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

    private static final String OIDC_DISCOVERY = ".well-known/openid-configuration";

    private AuthorizationServiceConfiguration mServiceConfig;

    private OktaAuthAccount(Builder builder) {
        mClientId = builder.mClientId;
        mRedirectUri = builder.mRedirectUri;
        mEndSessionRedirectUri = builder.mEndSessionRedirectUri;
        mDiscoveryUri = builder.mDiscoveryUri;
        mScopes = builder.mScopes;
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

    boolean isConfigured() {
        return mServiceConfig != null;
    }

    AuthorizationServiceConfiguration getServiceConfig() {
        return mServiceConfig;
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