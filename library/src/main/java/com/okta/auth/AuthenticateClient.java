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
import com.okta.auth.http.HttpConnection;
import com.okta.auth.http.HttpConnectionFactory;
import com.okta.auth.http.requests.AuthorizedRequest;
import com.okta.auth.http.requests.ConfigurationRequest;
import com.okta.auth.http.requests.HttpRequest;
import com.okta.auth.http.HttpResponse;
import com.okta.auth.http.requests.HttpRequestBuilder;
import com.okta.auth.http.requests.TokenExchangeRequest;
import com.okta.openid.appauth.AuthorizationException;
import com.okta.openid.appauth.AuthorizationManagementRequest;
import com.okta.openid.appauth.AuthorizationManagementResponse;
import com.okta.openid.appauth.AuthorizationRequest;
import com.okta.openid.appauth.AuthorizationResponse;
import com.okta.openid.appauth.AuthorizationServiceConfiguration;
import com.okta.openid.appauth.AuthorizationServiceDiscovery;
import com.okta.openid.appauth.EndSessionRequest;
import com.okta.openid.appauth.EndSessionResponse;
import com.okta.openid.appauth.ResponseTypeValues;
import com.okta.openid.appauth.TokenResponse;
import com.okta.openid.appauth.internal.Logger;

import org.json.JSONException;
import org.json.JSONObject;

import java.lang.ref.WeakReference;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;

import static android.app.Activity.RESULT_CANCELED;
import static com.okta.auth.OktaAuthenticationActivity.EXTRA_AUTH_URI;
import static com.okta.auth.OktaAuthenticationActivity.EXTRA_TAB_OPTIONS;
import static com.okta.auth.http.requests.HttpRequest.Type.TOKEN_EXCHANGE;
import static com.okta.openid.appauth.AuthorizationException.GeneralErrors.USER_CANCELED_AUTH_FLOW;
import static com.okta.openid.appauth.AuthorizationException.RegistrationRequestErrors.INVALID_REDIRECT_URI;

public final class AuthenticateClient {
    private static final String TAG = AuthenticateClient.class.getSimpleName();
    private static final String AUTH_REQUEST_PREF = "AuthRequest";
    private static final String AUTH_RESPONSE_PREF = "AuthResponse";
    private static final String AUTH_EXCEPTION_PREF = AuthenticateClient.class.getCanonicalName() + "AuthException";
    //need to restore auth.
    private static final String AUTH_RESTORE_PREF = AuthenticateClient.class.getCanonicalName() + ".AuthRestore";

    private WeakReference<Activity> mActivity;
    private OIDCAccount mOIDCAccount;
    private AuthenticationPayload mPayload;
    private int mCustomTabColor;

    private ThreadDispatcher mDispatcher;
    private AuthorizationManagementRequest mAuthRequest;
    private AuthorizationResponse mAuthResponse;
    private EndSessionResponse mEndSessionResponse;
    private HttpConnectionFactory mConnectionFactory;
    private ResultCallback<Boolean, AuthorizationException> mResultCb;
    private static boolean sResultHandled = false;
    private HttpRequest mCurrentHttpRequest;
    public static final int REQUEST_CODE_SIGN_IN = 100;
    public static final int REQUEST_CODE_SIGN_OUT = 101;

    private AuthenticateClient(@NonNull Builder builder) {
        mConnectionFactory = builder.mConnectionFactory;
        mOIDCAccount = builder.mOIDCAccount;
        mCustomTabColor = builder.mCustomTabColor;
        mPayload = builder.mPayload;
        mDispatcher = new ThreadDispatcher(builder.mCallbackExecutor);
    }

    private void registerActivityLifeCycle(@NonNull final Activity activity) {
        mActivity = new WeakReference<>(activity);
        mActivity.get().getApplication().registerActivityLifecycleCallbacks(new EmptyActivityLifeCycle() {
            @Override
            public void onActivitySaveInstanceState(Activity activity, Bundle outState) {
                if (mActivity != null && mActivity.get() == activity) {
                    persist();
                }
            }

            @Override
            public void onActivityDestroyed(Activity activity) {
                if (mActivity != null && mActivity.get() == activity) {
                    stop();
                    mActivity.get().getApplication().unregisterActivityLifecycleCallbacks(this);
                }
            }
        });
    }

    //TODO separate saving instance state to requests.
    private void persist() {
        SharedPreferences prefs = mActivity.get().getSharedPreferences(AuthenticateClient.class.getCanonicalName(), Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putBoolean(AUTH_RESTORE_PREF, true);
        if (mAuthRequest != null) {
            editor.putString(AUTH_REQUEST_PREF, mAuthRequest.jsonSerializeString());
        }
        if (mAuthResponse != null) {
            editor.putString(AUTH_RESPONSE_PREF, mAuthResponse.jsonSerializeString());
        }
        if (mOIDCAccount != null) {
            mOIDCAccount.persist(editor);
        }
        editor.apply();
    }

    private void restore(Activity activity) {
        SharedPreferences prefs = activity.getSharedPreferences(AuthenticateClient.class.getCanonicalName(), Context.MODE_PRIVATE);
        if (prefs.getBoolean(AUTH_RESTORE_PREF, false)) {
            try {
                String json = prefs.getString(AUTH_REQUEST_PREF, null);
                if (json != null) {
                    mAuthRequest = AuthorizationManagementRequest.jsonDeserialize(json);
                }
                json = prefs.getString(AUTH_RESPONSE_PREF, null);
                if (json != null) {
                    mAuthResponse = AuthorizationResponse.jsonDeserialize(json);
                }
                mOIDCAccount.restore(prefs);
                clearPreferences();
            } catch (JSONException ex) {
                //NO-OP
            }
        }
    }

    private void clearPreferences() {
        SharedPreferences prefs = mActivity.get()
                .getSharedPreferences(AuthenticateClient.class.getCanonicalName(),
                        Context.MODE_PRIVATE);
        prefs.edit().remove(AUTH_RESPONSE_PREF)
                .remove(AUTH_REQUEST_PREF)
                .remove(AUTH_RESTORE_PREF)
                .apply();
    }
    //end

    private void cancelCurrentRequest() {
        if (mCurrentHttpRequest != null) {
            mCurrentHttpRequest.cancelRequest();
            mCurrentHttpRequest = null;
        }
    }

    public ConfigurationRequest configurationRequest() {
        cancelCurrentRequest();
        mCurrentHttpRequest = HttpRequestBuilder.newRequest()
                .request(HttpRequest.Type.CONFIGURATION)
                .connectionFactory(mConnectionFactory)
                .account(mOIDCAccount).createRequest();
        return (ConfigurationRequest) mCurrentHttpRequest;
    }

    public AuthorizedRequest userProfileRequest() {
        cancelCurrentRequest();
        mCurrentHttpRequest = HttpRequestBuilder.newRequest()
                .request(HttpRequest.Type.PROFILE)
                .connectionFactory(mConnectionFactory)
                .account(mOIDCAccount).createRequest();
        return (AuthorizedRequest) mCurrentHttpRequest;
    }

    public AuthorizedRequest authorizedRequest(@NonNull Uri uri, @Nullable Map<String, String> properties, @Nullable Map<String, String> postParameters,
                                               @NonNull HttpConnection.RequestMethod method) {
        cancelCurrentRequest();
        mCurrentHttpRequest = HttpRequestBuilder.newRequest()
                .request(HttpRequest.Type.AUTHORIZED)
                .connectionFactory(mConnectionFactory)
                .account(mOIDCAccount)
                .uri(uri)
                .properties(properties)
                .postParameters(postParameters)
                .createRequest();
        return (AuthorizedRequest) mCurrentHttpRequest;
    }

    public void getUserProfile(final RequestCallback<JSONObject, AuthorizationException> cb) {
        cancelCurrentRequest();
        AuthorizedRequest request = userProfileRequest();
        request.dispatchRequest(mDispatcher, cb);
    }

    @AnyThread
    public void logIn(@NonNull final Activity activity, @NonNull final RequestCallback<Boolean, AuthorizationException> cb) {
        if (mOIDCAccount.haveConfiguration()) {
            authenticate(activity, cb);
        } else {
            ConfigurationRequest request = configurationRequest();
            mCurrentHttpRequest = request;
            request.dispatchRequest(mDispatcher, new RequestCallback<AuthorizationServiceDiscovery, AuthorizationException>() {
                @Override
                public void onSuccess(@NonNull AuthorizationServiceDiscovery result) {
                    mOIDCAccount.setServiceConfig(new AuthorizationServiceConfiguration(result));
                    authenticate(activity, cb);
                }

                @Override
                public void onError(String error, AuthorizationException exception) {
                    mDispatcher.execute(() -> cb.onError("can't obtain discovery doc", exception));
                }
            });
        }
    }

    private void authenticate(@NonNull final Activity activity, @NonNull final RequestCallback<Boolean, AuthorizationException> cb) {
        try {
            authenticateWithBrowser(activity);
        } catch (AuthorizationException ae) {
            mDispatcher.execute(() -> cb.onError("Invalid redirect or discovery document", ae));
        }
    }

    @AnyThread
    public void logOut(@NonNull final Activity activity, @NonNull final RequestCallback<Boolean, AuthorizationException> cb) {
        sResultHandled = false;
        if (mOIDCAccount.isLoggedIn()) {
            registerActivityLifeCycle(activity);
            mAuthRequest = new EndSessionRequest(
                    mOIDCAccount.getServiceConfig(),
                    mOIDCAccount.getIdToken(),
                    mOIDCAccount.getEndSessionRedirectUri());
            Intent intent = new Intent(mActivity.get(), OktaAuthenticationActivity.class);
            intent.putExtra(EXTRA_AUTH_URI, mAuthRequest.toUri());
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
            mActivity.get().startActivityForResult(intent, REQUEST_CODE_SIGN_OUT);
        } else {
            cb.onSuccess(true);
        }
    }

    //Code exchange
    public void handleAuthResult(Activity activity, int requestCode, int resultCode, Intent data, ResultCallback<Boolean, AuthorizationException> cb) {
        if (requestCode != REQUEST_CODE_SIGN_IN && requestCode != REQUEST_CODE_SIGN_OUT || sResultHandled) {
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
            responseData = extractResponseData(activity, responseUri);
        } catch (AuthorizationException ex) {
            mResultCb.onError("Failed to extract OAuth2 response from redirect", ex);
            return;
        }

        AuthorizationManagementResponse response =
                AuthorizationManagementResponse.fromIntent(responseData);
        AuthorizationException ex = AuthorizationException.fromIntent(responseData);

        if (ex != null || response == null) {
            mResultCb.onError("Authorization flow failed: ", ex);
        } else if (requestCode == REQUEST_CODE_SIGN_IN) {
            mAuthResponse = (AuthorizationResponse) response;
            codeExchange();
        } else {
            mEndSessionResponse = (EndSessionResponse) response;
            //TODO revoke tokens?
            mResultCb.onSuccess(true);
        }
        clearPreferences();
        sResultHandled = true;
    }

    private void stop() {
        mResultCb = null;
        cancelCurrentRequest();
        mDispatcher.shutdown();
    }

    @AnyThread
    public void authenticateWithBrowser(Activity activity) throws AuthorizationException {
        sResultHandled = false;
        registerActivityLifeCycle(activity);
        if (mOIDCAccount.haveConfiguration()) {
            mAuthRequest = createAuthRequest();
            if (!isRedirectUrisRegistered(mOIDCAccount.getRedirectUri())) {
                Log.e(TAG, "No uri registered to handle redirect or multiple applications registered");
                throw INVALID_REDIRECT_URI;
            }
            activity.startActivityForResult(createAuthIntent(), REQUEST_CODE_SIGN_IN);
        } else {
            throw AuthorizationException.GeneralErrors.INVALID_DISCOVERY_DOCUMENT;
        }
    }

    private AuthorizationRequest createAuthRequest() {
        AuthorizationRequest.Builder authRequestBuilder = new AuthorizationRequest.Builder(
                mOIDCAccount.getServiceConfig(),
                mOIDCAccount.getClientId(),
                ResponseTypeValues.CODE,
                mOIDCAccount.getRedirectUri())
                .setScopes(mOIDCAccount.getScopes());

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

    @WorkerThread
    private void codeExchange() {
        mCurrentHttpRequest = HttpRequestBuilder.newRequest().request(TOKEN_EXCHANGE).account(mOIDCAccount)
                .authRequest(mAuthRequest)
                .authResponse(mAuthResponse)
                .createRequest();

        ((TokenExchangeRequest) mCurrentHttpRequest).dispatchRequest(mDispatcher, new RequestCallback<TokenResponse, AuthorizationException>() {
            @Override
            public void onSuccess(@NonNull TokenResponse result) {
                mOIDCAccount.setTokenResponse(result);
                mDispatcher.execute(() -> mResultCb.onSuccess(true));
            }

            @Override
            public void onError(String error, AuthorizationException exception) {
                mDispatcher.execute(() -> mResultCb.onError("Failed to complete exchange request", exception));
            }
        });
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

    private Intent extractResponseData(Activity activity, Uri responseUri) throws AuthorizationException {
        if (responseUri.getQueryParameterNames().contains(AuthorizationException.PARAM_ERROR)) {
            throw AuthorizationException.fromOAuthRedirect(responseUri);
        } else {
            if (mAuthRequest == null) {
                restore(activity);
                if (mAuthRequest == null) {
                    throw USER_CANCELED_AUTH_FLOW;
                }
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
        private Executor mCallbackExecutor;
        private HttpConnectionFactory mConnectionFactory;
        private OIDCAccount mOIDCAccount;
        private AuthenticationPayload mPayload;
        private int mCustomTabColor;

        public Builder() {
        }

        public AuthenticateClient create() {
            return new AuthenticateClient(this);
        }

        public Builder withAccount(@NonNull OIDCAccount account) {
            mOIDCAccount = account;
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

        public Builder callbackExecutor(Executor executor) {
            mCallbackExecutor = executor;
            return this;
        }

        public Builder httpConnectionFactory(HttpConnectionFactory connectionFactory) {
            mConnectionFactory = connectionFactory;
            return this;
        }
    }
}