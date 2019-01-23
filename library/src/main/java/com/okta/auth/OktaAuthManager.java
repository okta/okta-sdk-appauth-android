package com.okta.auth;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.support.annotation.ColorInt;
import android.support.annotation.NonNull;
import android.support.annotation.WorkerThread;
import android.support.customtabs.CustomTabsIntent;
import android.text.TextUtils;
import android.util.Log;

import com.okta.appauth.android.AuthenticationPayload;

import net.openid.appauth.AppAuthConfiguration;
import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationManagementResponse;
import net.openid.appauth.AuthorizationRequest;
import net.openid.appauth.AuthorizationResponse;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.ResponseTypeValues;
import net.openid.appauth.internal.Logger;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static android.app.Activity.RESULT_CANCELED;
//import static com.okta.auth.OktaAuthenticationActivity.EXTRA_AUTH_INTENT;
import static com.okta.auth.OktaAuthenticationActivity.EXTRA_AUTH_URI;
import static com.okta.auth.OktaAuthenticationActivity.EXTRA_TAB_OPTIONS;

public class OktaAuthManager {
    private static final String TAG = OktaAuthManager.class.getSimpleName();

    //Persist options default is shared pref.
    public enum Persist {
        DEFAULT, SECURE, CUSTOM
    }

    //login method. currently only NATIVE and BROWSER.
    public enum LoginMethod {
        BROWSER, NATIVE
    }

    private Activity mActivity;
    private OktaAuthAccount mOktaAuthAccount;
    private AuthorizationCallback mCallback;
    private Persist mPersistOption;
    private AuthenticationPayload mPayload;
    private int mCustomTabColor;

    private ExecutorService mExecutor;

    private OktaClientAPI mOktaClient;
    private AuthorizationService mService;
    private AuthorizationRequest mAuthRequest;
    private AuthorizationResponse mAuthResponse;

    private LoginMethod mMethod;

    private static final int REQUEST_CODE = 100;

    private OktaAuthManager(@NonNull Builder builder) {
        mActivity = builder.mActivity;
        mOktaAuthAccount = builder.mOktaAuthAccount;
        mCallback = builder.mCallback;
        mPersistOption = builder.mPersistOption;
        mCustomTabColor = builder.mCustomTabColor;
        mPayload = builder.mPayload;
        mMethod = builder.mMethod;
        mExecutor = Executors.newSingleThreadExecutor();

    }

    //https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
    public void startAuthorization() {
        if (!mOktaAuthAccount.isConfigured()) {
            mCallback.onStatus("configuration");
            mExecutor.submit(() -> {
                try {
                    mOktaAuthAccount.obtainConfiguration();
                } catch (AuthorizationException ae) {
                    Log.d(TAG, "", ae);
                    mCallback.onError("", ae);
                }
            });
        }
        if (mMethod == LoginMethod.BROWSER) {
            mExecutor.submit(this::authenticate);
        } else if (mMethod == LoginMethod.NATIVE) {
            //TODO start native login flow.
        }
    }

    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode != REQUEST_CODE) {
            return;
        }
        if (resultCode == RESULT_CANCELED) {
            mCallback.onCancel();
            return;
        }
        Uri responseUri = data.getData();
        Intent responseData = extractResponseData(responseUri);
        if (responseData == null) {
            Logger.error("Failed to extract OAuth2 response from redirect");
            mCallback.onError("Failed to extract OAuth2 response from redirect", null);
            return;
        }
        //TODO handle other response types.
        AuthorizationManagementResponse response =
                AuthorizationManagementResponse.fromIntent(responseData);
        AuthorizationException ex = AuthorizationException.fromIntent(responseData);

        if (ex != null || response == null) {
            Log.w(TAG, "Authorization flow failed: " + ex);
            mCallback.onCancel();
        } else if (response instanceof AuthorizationResponse) {
            mAuthResponse = (AuthorizationResponse) response;
            mCallback.onSuccess(mAuthResponse);
        } else {
            mCallback.onCancel();
        }
    }

    public void onDestroy() {
        if (mService != null) {
            mService.dispose();
        }
    }

    public AuthorizationService getAuthService() {
        return mService;
    }

    //TODO
    @WorkerThread
    private void authenticate() {
        if (mOktaAuthAccount.isConfigured()) {
            mAuthRequest = createAuthRequest();
            if (mService != null) {
                mService.dispose();
            }
            //TODO remove
            mService = new AuthorizationService(mActivity, new AppAuthConfiguration.Builder().build());
            Intent intent = createAuthIntent();
            mActivity.startActivityForResult(intent, REQUEST_CODE);
        }
    }

    @WorkerThread
    private Intent createAuthIntent() {
        //CustomTabsIntent.Builder intentBuilder = mService.createCustomTabsIntentBuilder(mAuthRequest.toUri());
        //intentBuilder.setToolbarColor(mCustomTabColor);

        //CustomTabsIntent tabsIntent = intentBuilder.build();
        //tabsIntent.intent.addFlags(Intent.FLAG_ACTIVITY_NO_HISTORY);
        //Intent browserIntent = mService.prepareAuthorizationRequestIntent(mAuthRequest, tabsIntent);
        Intent intent = new Intent(mActivity, OktaAuthenticationActivity.class);
        intent.putExtra(EXTRA_AUTH_URI, mAuthRequest.toUri());
        //intent.putExtra(EXTRA_AUTH_INTENT, browserIntent);
        intent.putExtra(EXTRA_TAB_OPTIONS, mCustomTabColor);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
        return intent;
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

    private Intent extractResponseData(Uri responseUri) {
        if (responseUri.getQueryParameterNames().contains(AuthorizationException.PARAM_ERROR)) {
            return AuthorizationException.fromOAuthRedirect(responseUri).toIntent();
        } else {
            //TODO mAuthRequest is null if Activity is destroyed.
            if (mAuthRequest == null) {

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

                return AuthorizationException.AuthorizationRequestErrors.STATE_MISMATCH.toIntent();
            }
            return response.toIntent();
        }
    }

    public static class Builder {
        private Activity mActivity;
        private OktaAuthAccount mOktaAuthAccount;
        private AuthorizationCallback mCallback;
        private Persist mPersistOption = Persist.DEFAULT;
        private AuthenticationPayload mPayload;
        private int mCustomTabColor;
        private LoginMethod mMethod = LoginMethod.BROWSER;

        public Builder(@NonNull Activity activity) {
            mActivity = activity;
        }

        public OktaAuthManager create() {
            return new OktaAuthManager(this);
        }

        public Builder withCallback(@NonNull AuthorizationCallback callback) {
            mCallback = callback;
            return this;
        }

        public Builder withAccount(@NonNull OktaAuthAccount account) {
            mOktaAuthAccount = account;
            return this;
        }

        public Builder withPersistOption(@NonNull Persist option) {
            mPersistOption = option;
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
    }
}