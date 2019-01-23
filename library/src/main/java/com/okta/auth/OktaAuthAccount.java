package com.okta.auth;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.support.annotation.NonNull;
import android.support.annotation.RawRes;
import android.support.annotation.WorkerThread;
import android.util.Log;

import com.okta.android.json.InvalidJsonDocumentException;
import com.okta.android.json.JsonParser;

import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationServiceConfiguration;
import net.openid.appauth.AuthorizationServiceDiscovery;
import net.openid.appauth.connectivity.DefaultConnectionBuilder;
import net.openid.appauth.internal.Logger;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.io.Writer;
import java.net.HttpURLConnection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
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

    private OktaAuthAccount() {
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

    //TODO change access
    public AuthorizationServiceConfiguration getServiceConfig() {
        return mServiceConfig;
    }

    @WorkerThread
    void obtainConfiguration() throws AuthorizationException {
        Log.i(TAG, "Retrieving OpenID discovery doc");
        InputStream is = null;
        AuthorizationException exception = null;
        try {
            HttpURLConnection conn = DefaultConnectionBuilder.INSTANCE.openConnection(getDiscoveryUri());
            conn.setRequestMethod("GET");
            conn.setDoInput(true);
            conn.connect();

            is = conn.getInputStream();
            if (is == null) {
                throw new IOException("Input stream must not be null");
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(is));
            Writer writer = new StringWriter();
            String line = reader.readLine();
            while (line != null) {
                writer.write(line);
                line = reader.readLine();
            }
            JSONObject json = new JSONObject(writer.toString());
            AuthorizationServiceDiscovery discovery =
                    new AuthorizationServiceDiscovery(json);
            mServiceConfig = new AuthorizationServiceConfiguration(discovery);
        } catch (IOException ex) {
            Logger.errorWithStack(ex, "Network error when retrieving discovery document");
            exception = AuthorizationException.fromTemplate(
                    AuthorizationException.GeneralErrors.NETWORK_ERROR,
                    ex);
        } catch (JSONException ex) {
            Logger.errorWithStack(ex, "Error parsing discovery document");
            exception = AuthorizationException.fromTemplate(
                    AuthorizationException.GeneralErrors.JSON_DESERIALIZATION_ERROR,
                    ex);
        } catch (AuthorizationServiceDiscovery.MissingArgumentException ex) {
            Logger.errorWithStack(ex, "Malformed discovery document");
            exception = AuthorizationException.fromTemplate(
                    AuthorizationException.GeneralErrors.INVALID_DISCOVERY_DOCUMENT,
                    ex);
        } finally {
            try {
                if (is != null) {
                    is.close();
                }
            } catch (IOException ignored) {
                // deliberately do nothing
            }
            if (exception != null) {
                mServiceConfig = null;
                throw exception;
            }
        }
    }

    public static class Builder {
        private Context mContext;
        private OktaAuthAccount mAuthProvider;

        public Builder(@NonNull Context context) {
            mContext = context;
            mAuthProvider = new OktaAuthAccount();
        }

        public OktaAuthAccount create() {
            if (!isRedirectUrisRegistered(mAuthProvider.mRedirectUri) || !isRedirectUrisRegistered(mAuthProvider.mEndSessionRedirectUri)) {
                throw new RuntimeException(
                        "redirect_uri or end_session_redirect_uri is not handled by activity "
                                + "in this app! "
                                + "Ensure that the appAuthRedirectScheme in your build.gradle file "
                                + "is correctly configured, or that an appropriate intent filter "
                                + "exists in your app manifest.");
            }
            return mAuthProvider;
        }

        public Builder clientId(@NonNull String clientId) {
            mAuthProvider.mClientId = clientId;
            return this;
        }

        public Builder redirectUri(@NonNull String redirect) {
            mAuthProvider.mRedirectUri = Uri.parse(redirect);
            return this;
        }

        public Builder endSessionRedirectUri(@NonNull String endSessionRedirect) {
            mAuthProvider.mEndSessionRedirectUri = Uri.parse(endSessionRedirect);
            return this;
        }

        public Builder discoveryUri(@NonNull String discoveryUri) {
            mAuthProvider.mDiscoveryUri = Uri.parse(discoveryUri);
            return this;
        }

        public Builder scopes(@NonNull String... scopes) {
            mAuthProvider.mScopes = new LinkedHashSet<>();
            Collections.addAll(mAuthProvider.mScopes, scopes);
            return this;
        }

        public OktaAuthAccount withResId(@RawRes int Id) {
            try (InputStream inputStream = mContext.getResources().openRawResource(Id)) {
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
            return mAuthProvider;
        }

        private void readConfiguration(@NonNull final JSONObject jsonObject)
                throws InvalidJsonDocumentException {
            JsonParser jsonParser = JsonParser.forJson(jsonObject);
            mAuthProvider.mClientId = jsonParser.getRequiredString(CLIENT_ID);
            mAuthProvider.mRedirectUri = jsonParser.getRequiredUri(REDIRECT_URI);
            mAuthProvider.mEndSessionRedirectUri = jsonParser.getRequiredUri(END_SESSION_REDIRECT_URI);
            mAuthProvider.mDiscoveryUri = jsonParser.getRequiredHttpsUri(DISCOVERY_URI)
                    .buildUpon().appendEncodedPath(OIDC_DISCOVERY).build();

            mAuthProvider.mScopes = new LinkedHashSet<>(jsonParser.getRequiredStringArray(SCOPES));
        }

        private boolean isRedirectUrisRegistered(Uri uri) {
            PackageManager pm = mContext.getPackageManager();
            List<ResolveInfo> resolveInfos = null;
            if (pm != null) {
                Intent intent = new Intent();
                intent.setAction(Intent.ACTION_VIEW);
                intent.addCategory(Intent.CATEGORY_BROWSABLE);
                intent.setData(uri);
                resolveInfos = pm.queryIntentActivities(intent, PackageManager.GET_RESOLVED_FILTER);
            }
            boolean found = false;
            if (resolveInfos != null) {
                for (ResolveInfo info : resolveInfos) {
                    ActivityInfo activityInfo = info.activityInfo;
                    if (activityInfo.name.equals(OktaRedirectActivity.class.getCanonicalName()) &&
                            activityInfo.packageName.equals(mContext.getPackageName())) {
                        found = true;
                    } else {
                        Log.w(TAG, "Warning! Multiple applications found registered with same scheme");
                        //Another installed app have same url scheme.
                        //return false as if no activity found to prevent hijacking of redirect.
                        return false;
                    }
                }
            }
            return found;
        }
    }
}