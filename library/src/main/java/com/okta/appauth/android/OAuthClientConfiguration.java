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

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.support.annotation.AnyThread;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.VisibleForTesting;
import android.util.Log;

import com.okta.android.json.InvalidJsonDocumentException;
import com.okta.android.json.JsonParser;
import okio.Buffer;
import okio.BufferedSource;
import okio.Okio;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.lang.ref.WeakReference;
import java.nio.charset.Charset;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * <p>
 * Holds the configuration for the okta-sdk-appauth-android library.
 * </p>
 * <p>
 * Retains a {@link WeakReference} to the configuration so multiple callers can access it without
 * needing to re-parse the resource, but without impacting memory adversely for
 * normal app operation.
 * </p>
 * <p>
 * Uses a JSON document for configuration so that users of this library could easily extend this
 * to fetch configuration dynamically for the application.
 * </p>
 */
@SuppressWarnings("WeakerAccess")
public class OAuthClientConfiguration {

    private static final String TAG = "OktaOAuthClientConfig";

    private static final AtomicReference<WeakReference<OAuthClientConfiguration>> INSTANCE_REF =
            new AtomicReference<>(new WeakReference<OAuthClientConfiguration>(null));

    @VisibleForTesting
    static final String PREFS_NAME = "OktaAppAuthConfig";
    @VisibleForTesting
    static final String KEY_LAST_HASH = "lastHash";

    @VisibleForTesting
    static final String OIDC_DISCOVERY = ".well-known/openid-configuration";

    private final SharedPreferences mPrefs;

    private final PackageManager mPackageManager;
    private final String mPackageName;

    private int mConfigHash;
    private String mConfigurationError;

    private String mClientId;
    private Uri mRedirectUri;
    private Uri mEndSessionRedirectUri;
    private Uri mDiscoveryUri;
    private Set<String> mScopes;

    /**
     * <p>
     * Retrieve the configuration object via the static {@link WeakReference} or construct a new
     * instance using the configuration provided via a resource file.
     * </p>
     * <p>
     * NOTE: The OAuthClientConfiguration may have an error after constructing. Call
     * {@link #isValid()} to ensure its validity.
     * </p>
     *
     * @param context The Context from which to get the application's resources
     * @return an OAuthClientConfiguration object
     */
    @AnyThread
    public static OAuthClientConfiguration getInstance(final Context context) {
        OAuthClientConfiguration config = INSTANCE_REF.get().get();
        if (config == null) {
            config = new OAuthClientConfiguration(
                    context.getApplicationContext(),
                    context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE),
                    context.getResources().openRawResource(R.raw.okta_app_auth_config)
            );
        }

        return config;
    }

    @VisibleForTesting
    OAuthClientConfiguration(
            final Context context,
            final SharedPreferences prefs,
            final InputStream configurationStream) {
        mPrefs = prefs;
        mPackageManager = context.getPackageManager();
        mPackageName = context.getPackageName();

        try {
            JSONObject jsonObject = fetchConfiguration(configurationStream);
            readConfiguration(jsonObject);
        } catch (InvalidJsonDocumentException ex) {
            mConfigurationError = ex.getMessage();
        }

        INSTANCE_REF.set(new WeakReference<>(this));
    }

    /**
     * Indicates whether the configuration has changed from the last known valid state.
     *
     * @return {@code true} if the configuration has changed since the last valid state;
     *     {@code false} otherwise
     */
    public boolean hasConfigurationChanged() {
        Integer lastKnownConfigHash = getLastKnownConfigHash();
        return lastKnownConfigHash == null || mConfigHash != lastKnownConfigHash;
    }

    private Integer getLastKnownConfigHash() {
        String hashString = mPrefs.getString(KEY_LAST_HASH, null);
        return hashString == null ? null : Integer.valueOf(hashString);
    }

    /**
     * Indicates that the current configuration should be accepted as the "last known valid"
     * configuration.
     */
    public void acceptConfiguration() {
        mPrefs.edit().putString(KEY_LAST_HASH, String.valueOf(mConfigHash)).apply();
    }

    /**
     * <p>
     * Fetches a JSONObject representing the configuration for this SDK. The Context for the
     * application is provided to allow the implementer access to the application environment.
     * </p>
     * <p>
     * The default implementation uses the resources at R.raw.okta_app_auth_config to retrieve
     * a JSON document. Callers may wish to use network calls or methods to configure this SDK.
     * Any errors encountered during the configuration fetching process should be wrapped in an
     * InvalidJsonDocumentException and thrown.
     * </p>
     *
     * @param configurationStream The InputStream with the configuration
     * @return A JSONObject containing the configuration needed for this SDK
     * @throws InvalidJsonDocumentException When the JSON cannot be fetched properly
     */
    protected JSONObject fetchConfiguration(final InputStream configurationStream)
            throws InvalidJsonDocumentException {
        BufferedSource configSource =
                Okio.buffer(Okio.source(configurationStream));
        Buffer configData = new Buffer();
        try {
            configSource.readAll(configData);
            return new JSONObject(configData.readString(Charset.forName("UTF-8")));
        } catch (IOException ex) {
            throw new InvalidJsonDocumentException(
                    "Failed to read configuration: " + ex.getMessage());
        } catch (JSONException ex) {
            throw new InvalidJsonDocumentException(
                    "Unable to parse configuration: " + ex.getMessage());
        }
    }

    @VisibleForTesting
    void readConfiguration(@NonNull final JSONObject jsonObject)
            throws InvalidJsonDocumentException {
        JsonParser jsonParser = JsonParser.forJson(jsonObject);


        mClientId = jsonParser.getRequiredString("client_id");
        mRedirectUri = jsonParser.getRequiredUri("redirect_uri");
        mEndSessionRedirectUri = jsonParser.getRequiredUri("end_session_redirect_uri");
        mDiscoveryUri = jsonParser.getRequiredHttpsUri("issuer_uri")
                .buildUpon().appendEncodedPath(OIDC_DISCOVERY).build();

        if (!isRedirectUrisRegistered()) {
            throw new InvalidJsonDocumentException(
                    "redirect_uri and end_session_redirect_uri is not handled by any activity "
                            + "in this app! "
                            + "Ensure that the appAuthRedirectScheme in your build.gradle file "
                            + "is correctly configured, or that an appropriate intent filter "
                            + "exists in your app manifest.");
        }


        mScopes = new LinkedHashSet<>(jsonParser.getRequiredStringArray("scopes"));

        //We can not take hash code directly from JSONObject
        //because JSONObject does not follow java has code contract
        mConfigHash = jsonObject.toString().hashCode();

        Log.d(TAG, String.format("Configuration loaded with: \n%s", this.toString()));
    }

    private boolean isRedirectUrisRegistered() {
        // ensure that the redirect URIs declared in the configuration is handled by some activity
        // in the app, by querying the package manager speculatively
        Intent redirectIntent = new Intent();
        redirectIntent.setPackage(mPackageName);
        redirectIntent.setAction(Intent.ACTION_VIEW);
        redirectIntent.addCategory(Intent.CATEGORY_BROWSABLE);
        // we need to check for only one of the uris because we have the same schema
        // for other redirect URIs in the app
        redirectIntent.setData(mRedirectUri);

        return !mPackageManager.queryIntentActivities(redirectIntent, 0).isEmpty();
    }

    /*
     * Accessors
     */

    /**
     * Indicates whether the current configuration is valid.
     *
     * @return {@code true} if there was no error when fetching nor reading the configuration;
     *     {@code false} otherwise
     */
    public boolean isValid() {
        return mConfigurationError == null;
    }

    /**
     * Returns a description of the configuration error if the configuration is invalid.
     *
     * @return The error description or {@code null} if no error exists
     */
    @Nullable
    public String getConfigurationError() {
        return mConfigurationError;
    }

    /**
     * Returns the Client ID defined by the configuration.
     *
     * @return The Client ID for this application
     */
    public String getClientId() {
        return mClientId;
    }

    /**
     * Returns the redirect uri to go to once the authorization flow is complete.
     * This will match schema of the app's registered Uri provided in manifest
     *
     * @return The Uri to redirect to once the authorization flow is complete
     */
    public Uri getRedirectUri() {
        return mRedirectUri;
    }

    /**
     * Returns the redirect uri to go to once the end session flow is complete.
     * This will match schema of the app's registered Uri provided in manifest
     *
     * @return The Uri to redirect to once the end session flow is complete
     */
    public Uri getEndSessionRedirectUri() {
        return mEndSessionRedirectUri;
    }

    /**
     * Returns the discovery uri for the authorization server. It is formed by appending the
     * well known location of the discovery document to the issuer.
     *
     * @return The Uri where the discovery document can be found
     */
    public Uri getDiscoveryUri() {
        return mDiscoveryUri;
    }

    /**
     * Returns the set of scopes defined by the configuration. These scopes can be used during
     * the authorization request for the user.
     *
     * @return The set of scopes defined by the configuration
     */
    public Set<String> getScopes() {
        return mScopes;
    }

}
