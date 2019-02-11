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

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Bundle;
import android.support.annotation.AnyThread;
import android.support.annotation.ColorInt;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.WorkerThread;
import android.text.TextUtils;
import android.util.Log;

import com.okta.appauth.android.AuthenticationPayload;
import com.okta.auth.http.HttpRequest;
import com.okta.auth.http.HttpResponse;
import com.okta.openid.appauth.AuthorizationException;
import com.okta.openid.appauth.AuthorizationManagementResponse;
import com.okta.openid.appauth.AuthorizationRequest;
import com.okta.openid.appauth.AuthorizationResponse;
import com.okta.openid.appauth.EndSessionRequest;
import com.okta.openid.appauth.IdToken;
import com.okta.openid.appauth.ResponseTypeValues;
import com.okta.openid.appauth.SystemClock;
import com.okta.openid.appauth.TokenRequest;
import com.okta.openid.appauth.TokenResponse;
import com.okta.openid.appauth.internal.Logger;
import com.okta.openid.appauth.internal.UriUtil;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static android.app.Activity.RESULT_CANCELED;
import static com.okta.auth.OktaAuthenticationActivity.EXTRA_AUTH_URI;
import static com.okta.auth.OktaAuthenticationActivity.EXTRA_TAB_OPTIONS;
import static com.okta.openid.appauth.AuthorizationException.GeneralErrors.USER_CANCELED_AUTH_FLOW;
import static com.okta.openid.appauth.AuthorizationException.RegistrationRequestErrors.INVALID_REDIRECT_URI;

public final class OktaAuthManager {
    private static final String TAG = OktaAuthManager.class.getSimpleName();
    private static final String AUTH_REQUEST_PREF = "AuthRequest";
    private static final String AUTH_RESPONSE_PREF = "AuthResponse";
    private static final String AUTH_EXCEPTION_PREF = OktaAuthManager.class.getCanonicalName() + "AuthException";
    //need to restore auth.
    private static final String AUTH_RESTORE_PREF = OktaAuthManager.class.getCanonicalName() + ".AuthRestore";

    //login method. currently only NATIVE and BROWSER_TAB.
    public enum LoginMethod {
        BROWSER_TAB, NATIVE
    }

    private WeakReference<Activity> mActivity;
    private OktaAuthAccount mOktaAuthAccount;
    private OktaClientAPI mOktaClient;
    private AuthenticationPayload mPayload;
    private String mUsername;
    private String mPassword;
    private int mCustomTabColor;

    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();
    private final MainThreadExecutor mMainThread = new MainThreadExecutor();
    private AuthorizationRequest mAuthRequest;
    private AuthorizationResponse mAuthResponse;
    //private ResultCallback mRequestCb;
    private RequestCallback<Boolean, AuthorizationException> mRequestCb;
    private ResultCallback mResultCb;
    private static final int REQUEST_CODE_SIGN_IN = 100;
    private static final int REQUEST_CODE_SIGN_OUT = 101;

    private OktaAuthManager(@NonNull Builder builder) {
        mActivity = builder.mActivity;
        mOktaAuthAccount = builder.mOktaAuthAccount;
        mCustomTabColor = builder.mCustomTabColor;
        mPayload = builder.mPayload;
        mOktaAuthAccount.mLoginMethod = builder.mMethod;
        mUsername = builder.mUsername;
        mPassword = builder.mPassword;
        restore();
        mActivity.get().getApplication().registerActivityLifecycleCallbacks(new EmptyActivityLifeCycle() {
            @Override
            public void onActivityDestroyed(Activity activity) {
                if (mActivity.get() == activity) {
                    persist(true);
                    stop();
                    if (mOktaClient != null) {
                        mOktaClient.stop();
                    }
                    mActivity.get().getApplication().unregisterActivityLifecycleCallbacks(this);
                }
            }
        });
    }

    @SuppressLint("ApplySharedPref")
    private void persist(boolean immediate) {
        SharedPreferences prefs = mActivity.get().getSharedPreferences(OktaAuthManager.class.getCanonicalName(), Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putBoolean(AUTH_RESTORE_PREF, true);
        if (mAuthRequest != null) {
            editor.putString(AUTH_REQUEST_PREF, mAuthRequest.jsonSerializeString());
        }
        if (mAuthResponse != null) {
            editor.putString(AUTH_RESPONSE_PREF, mAuthResponse.jsonSerializeString());
        }
        if (mOktaAuthAccount != null) {
            mOktaAuthAccount.persist(editor);
        }
        if (immediate) {
            editor.commit(); //need to commit immediately since activity is being destroyed.
        } else {
            editor.apply();
        }
    }

    private void restore() {
        SharedPreferences prefs = mActivity.get().getSharedPreferences(OktaAuthManager.class.getCanonicalName(), Context.MODE_PRIVATE);
        if (prefs.getBoolean(AUTH_RESTORE_PREF, false)) {
            try {
                mAuthRequest = AuthorizationRequest.jsonDeserialize(prefs.getString(AUTH_REQUEST_PREF, null));
                mAuthResponse = AuthorizationResponse.jsonDeserialize(prefs.getString(AUTH_RESPONSE_PREF, null));
                mOktaAuthAccount.restore(prefs);
                prefs.edit().putBoolean(AUTH_RESTORE_PREF, false).apply();
            } catch (JSONException ex) {
                //do nothing
            } catch (NullPointerException np) {
                //do nothing
            }
        }
    }

    //https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
    public void startAuthorization(@NonNull final RequestCallback<Boolean, AuthorizationException> cb) {
        mRequestCb = cb;
        if (mOktaAuthAccount.haveConfiguration()) {
            mExecutor.submit(this::authenticate);
        } else {
            mExecutor.submit(() -> {
                try {
                    mOktaAuthAccount.obtainConfiguration();
                    if (mOktaAuthAccount.mLoginMethod == LoginMethod.BROWSER_TAB && !isRedirectUrisRegistered(mOktaAuthAccount.getRedirectUri())) {
                        mMainThread.execute(() -> mRequestCb.onError("No uri registered to handle redirect", INVALID_REDIRECT_URI));
                        return;
                    }
                    authenticate();
                } catch (AuthorizationException ae) {
                    mMainThread.execute(() -> mRequestCb.onError("can't obtain discovery doc", ae));
                }
            });
        }
    }

    @AnyThread
    public void logOut(final RequestCallback<Boolean, AuthorizationException> cb) {
        if (mOktaAuthAccount.isLoggedIn()) {
            if (mOktaAuthAccount.mLoginMethod == OktaAuthManager.LoginMethod.BROWSER_TAB) {
                EndSessionRequest request = new EndSessionRequest(
                        mOktaAuthAccount.getServiceConfig(),
                        mOktaAuthAccount.mTokenResponse.idToken,
                        mOktaAuthAccount.getEndSessionRedirectUri());
                Intent intent = new Intent(mActivity.get(), OktaAuthenticationActivity.class);
                intent.putExtra(EXTRA_AUTH_URI, request.toUri());
                intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
                mActivity.get().startActivityForResult(intent, REQUEST_CODE_SIGN_OUT);
            } else {
                //TODO revoke tokens.
            }
        } else {
            cb.onSuccess(true);
        }
    }

    public @Nullable
    OktaClientAPI getAuthorizedClient() {
        if (mOktaClient == null && mOktaAuthAccount != null && mOktaAuthAccount.isLoggedIn()) {
            mOktaClient = new OktaClientAPI(mOktaAuthAccount);
        }
        return mOktaClient;
    }

    public void handleAuthResult(int requestCode, int resultCode, Intent data, ResultCallback cb) {
        if (requestCode != REQUEST_CODE_SIGN_IN) {
            return;
        }
        mResultCb = cb;
        if (resultCode == RESULT_CANCELED) {
            mResultCb.onCancel();
            return;
        }

        Uri responseUri = data.getData();
        Intent responseData;
        try {
            responseData = extractResponseData(responseUri);
        } catch (AuthorizationException ex) {
            mResultCb.onError("Failed to extract OAuth2 response from redirect", ex);
            return;
        }
        //TODO handle other response types.
        AuthorizationManagementResponse response =
                AuthorizationManagementResponse.fromIntent(responseData);
        AuthorizationException ex = AuthorizationException.fromIntent(responseData);

        if (ex != null || response == null) {
            mResultCb.onError("Authorization flow failed: ", ex);
        } else if (response instanceof AuthorizationResponse) {
            mAuthResponse = (AuthorizationResponse) response;
            mExecutor.submit(this::codeExchange);
        } else {
            mResultCb.onCancel();
        }
    }

    private void stop() {
        mResultCb = null;
        mRequestCb = null;
        mMainThread.shutdown();
        mExecutor.shutdownNow();
    }

    @WorkerThread
    private void authenticate() {
        if (mOktaAuthAccount.haveConfiguration()) {
            if (mOktaAuthAccount.mLoginMethod == LoginMethod.BROWSER_TAB) {
                mAuthRequest = createAuthRequest();
                mActivity.get().startActivityForResult(createAuthIntent(), REQUEST_CODE_SIGN_IN);
            } else if (mOktaAuthAccount.mLoginMethod == LoginMethod.NATIVE) {
                //TODO start native login flow.
            }
        } else {
            mMainThread.execute(() -> mRequestCb.onError("Invalid account information",
                    AuthorizationException.GeneralErrors.INVALID_DISCOVERY_DOCUMENT));
        }
    }

    @WorkerThread
    private void codeExchange() {
        AuthorizationException exception;
        HttpResponse response = null;
        try {
            TokenRequest tokenRequest = mAuthResponse.createTokenExchangeRequest();
            Map<String, String> parameters = tokenRequest.getRequestParameters();
            parameters.put(TokenRequest.PARAM_CLIENT_ID, mAuthRequest.clientId);

            response = new HttpRequest.Builder().setRequestMethod(HttpRequest.RequestMethod.POST)
                    .setUri(mOktaAuthAccount.getServiceConfig().tokenEndpoint)
                    .setRequestProperty("Accept", "application/json")
                    .setPostParameters(parameters)
                    .create()
                    .executeRequest();

            JSONObject json = response.asJson();
            if (json.has(AuthorizationException.PARAM_ERROR)) {
                try {
                    final String error = json.getString(AuthorizationException.PARAM_ERROR);
                    final AuthorizationException ex = AuthorizationException.fromOAuthTemplate(
                            AuthorizationException.TokenRequestErrors.byString(error),
                            error,
                            json.optString(AuthorizationException.PARAM_ERROR_DESCRIPTION, null),
                            UriUtil.parseUriIfAvailable(
                                    json.optString(AuthorizationException.PARAM_ERROR_URI)));
                    mMainThread.execute(() -> mResultCb.onError(error, ex));
                } catch (JSONException jsonEx) {
                    mMainThread.execute(() -> mResultCb.onError("error", AuthorizationException.fromTemplate(
                            AuthorizationException.GeneralErrors.JSON_DESERIALIZATION_ERROR,
                            jsonEx)));
                }
                return;
            }

            try {
                mOktaAuthAccount.mTokenResponse = new TokenResponse.Builder(tokenRequest).fromResponseJson(json).build();
            } catch (JSONException jsonEx) {
                mMainThread.execute(() -> mResultCb.onError("JsonException", AuthorizationException.fromTemplate(
                        AuthorizationException.GeneralErrors.JSON_DESERIALIZATION_ERROR,
                        jsonEx)));
                return;
            }

            if (mOktaAuthAccount.mTokenResponse.idToken != null) {
                IdToken idToken;
                try {
                    idToken = IdToken.from(mOktaAuthAccount.mTokenResponse.idToken);
                } catch (IdToken.IdTokenException | JSONException ex) {
                    mMainThread.execute(() -> mResultCb.onError("Unable to parse ID Token",
                            AuthorizationException.fromTemplate(
                                    AuthorizationException.GeneralErrors.ID_TOKEN_PARSING_ERROR,
                                    ex)));
                    return;
                }

                try {
                    idToken.validate(tokenRequest, SystemClock.INSTANCE);
                } catch (AuthorizationException ex) {
                    mMainThread.execute(() -> mResultCb.onError("IdToken validation error", ex));
                    return;
                }
            }
            mMainThread.execute(() -> mResultCb.onSuccess(mOktaClient = new OktaClientAPI(mOktaAuthAccount)));
        } catch (IOException ex) {
            Logger.debugWithStack(ex, "Failed to complete exchange request");
            exception = AuthorizationException.fromTemplate(
                    AuthorizationException.GeneralErrors.NETWORK_ERROR, ex);
            mMainThread.execute(() -> mResultCb.onError("Failed to complete exchange request", exception));
        } catch (JSONException ex) {
            Logger.debugWithStack(ex, "Failed to complete exchange request");
            exception = AuthorizationException.fromTemplate(
                    AuthorizationException.GeneralErrors.JSON_DESERIALIZATION_ERROR, ex);
            mMainThread.execute(() -> mResultCb.onError("Failed to complete exchange request", exception));
        } finally {
            if (response != null) {
                response.disconnect();
            }
        }
    }

    private Intent createAuthIntent() {
        Intent intent = new Intent(mActivity.get(), OktaAuthenticationActivity.class);
        intent.putExtra(EXTRA_AUTH_URI, mAuthRequest.toUri());
        intent.putExtra(EXTRA_TAB_OPTIONS, mCustomTabColor);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
        return intent;
    }

    private boolean isRedirectUrisRegistered(@NonNull Uri uri) {
        PackageManager pm = mActivity.get().getPackageManager();
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
                        activityInfo.packageName.equals(mActivity.get().getPackageName())) {
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

    private AuthorizationRequest createAuthRequest() {
        AuthorizationRequest.Builder authRequestBuilder = new AuthorizationRequest.Builder(
                mOktaAuthAccount.getServiceConfig(),
                mOktaAuthAccount.getClientId(),
                ResponseTypeValues.CODE,
                mOktaAuthAccount.getRedirectUri())
                .setScopes(mOktaAuthAccount.getScopes());

        if (mPayload != null) {
            authRequestBuilder.setAdditionalParameters(mPayload.getAdditionalParameters());
            if (!TextUtils.isEmpty(mPayload.toString())) {
                authRequestBuilder.setState(mPayload.getState());
            }
            if (!TextUtils.isEmpty(mPayload.getLoginHint())) {
                authRequestBuilder.setLoginHint(mPayload.getLoginHint());
            }
        }
        return authRequestBuilder.build();
    }

    private Intent extractResponseData(Uri responseUri) throws AuthorizationException {
        if (responseUri.getQueryParameterNames().contains(AuthorizationException.PARAM_ERROR)) {
            throw AuthorizationException.fromOAuthRedirect(responseUri);
        } else {
            //TODO mAuthRequest is null if Activity is destroyed.
            if (mAuthRequest == null) {
                throw USER_CANCELED_AUTH_FLOW;
            }
            AuthorizationManagementResponse response = AuthorizationManagementResponse
                    .buildFromRequest(mAuthRequest, responseUri);

            if (mAuthRequest.getState() == null && response.getState() != null
                    || (mAuthRequest.getState() != null && !mAuthRequest.getState()
                    .equals(response.getState()))) {

                Logger.warn("State returned in authorization response (%s) does not match state "
                                + "from request (%s) - discarding response",
                        response.getState(),
                        mAuthRequest.getState());
                throw AuthorizationException.AuthorizationRequestErrors.STATE_MISMATCH;
            }
            return response.toIntent();
        }
    }

    public static final class Builder {
        private WeakReference<Activity> mActivity;
        private OktaAuthAccount mOktaAuthAccount;
        private AuthenticationPayload mPayload;
        private int mCustomTabColor;
        private String mUsername;
        private String mPassword;
        private LoginMethod mMethod = LoginMethod.BROWSER_TAB;

        public Builder(Activity activity) {
            mActivity = new WeakReference<>(activity);
        }

        public OktaAuthManager create() {
            return new OktaAuthManager(this);
        }

        public Builder withAccount(@NonNull OktaAuthAccount account) {
            mOktaAuthAccount = account;
            return this;
        }

        public Builder withPayload(@NonNull AuthenticationPayload payload) {
            mPayload = payload;
            return this;
        }

        public Builder withTabColor(@ColorInt int customTabColor) {
            mCustomTabColor = customTabColor;
            return this;
        }

        public Builder withMethod(@NonNull LoginMethod method) {
            mMethod = method;
            return this;
        }

        public Builder withCredential(@NonNull String username, @NonNull String password) {
            mUsername = username;
            mPassword = password;
            return this;
        }
    }
}