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

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.support.annotation.MainThread;
import android.support.annotation.Nullable;
import android.support.annotation.VisibleForTesting;
import android.support.annotation.WorkerThread;
import android.util.Log;

import net.openid.appauth.AppAuthConfiguration;
import net.openid.appauth.AuthState;
import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationManagementResponse;
import net.openid.appauth.AuthorizationResponse;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.ClientAuthentication;
import net.openid.appauth.TokenResponse;
import net.openid.appauth.internal.Logger;

/**
 * This Activity is used to manage Authorization and end of session requests.
 * It will trade the authorization code for the token and notify whether
 * end of session have been performed correctly
 */
public class OktaManagementActivity extends Activity {

    private static final String TAG = "OktaAuthTknExchngActvty";

    @VisibleForTesting
    static final String KEY_COMPLETE_INTENT = "completeIntent";
    @VisibleForTesting
    static final String KEY_CANCEL_INTENT = "cancelIntent";

    private AuthorizationService mAuthService;
    private AuthStateManager mStateManager;

    @VisibleForTesting
    PendingIntent mCompleteIntent;
    @VisibleForTesting
    PendingIntent mCancelIntent;

    /**
     * Creates an Intent to drive the token exchange to this Activity. Takes two PendingIntents as
     * parameters to direct the flow upon completion or cancellation/failure respectively.
     *
     * @param context The context in which to create the Intent
     * @param completeIntent The PendingIntent to direct the flow once the token exchange completes
     * @param cancelIntent The PendingIntent to direct the flow if the authentication is cancelled
     *     or if the authorization fails
     * @return A PendingIntent that will start this Activity
     */
    static PendingIntent createStartIntent(
            Context context,
            PendingIntent completeIntent,
            PendingIntent cancelIntent) {
        Intent tokenExchangeIntent = new Intent(context, OktaManagementActivity.class);
        tokenExchangeIntent.putExtra(KEY_COMPLETE_INTENT, completeIntent);
        tokenExchangeIntent.putExtra(KEY_CANCEL_INTENT, cancelIntent);
        return PendingIntent.getActivity(context, 0, tokenExchangeIntent, 0);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mStateManager = AuthStateManager.getInstance(this);

        mAuthService = new AuthorizationService(
                this,
                new AppAuthConfiguration.Builder()
                        .build());

        if (savedInstanceState == null) {
            extractState(getIntent().getExtras());
        } else {
            extractState(savedInstanceState);
        }
    }

    @Override
    protected void onStart() {
        super.onStart();
        OAuthClientConfiguration config = OAuthClientConfiguration.getInstance(this);
        if (config.hasConfigurationChanged()) {
            signOut();
            return;
        }
        // the stored AuthState is incomplete, so check if we are currently receiving the result of
        // the authorization flow from the browser.
        AuthorizationManagementResponse response =
                AuthorizationManagementResponse.fromIntent(getIntent());
        AuthorizationException ex = AuthorizationException.fromIntent(getIntent());

        if (ex != null || response == null) {
            Log.w(TAG, "Authorization flow failed: " + ex);
            sendPendingIntent(mCancelIntent);
        } else if (isLoginFlow(response)) {
            runLoginFlow((AuthorizationResponse) response, ex);
        } else {
            sendPendingIntent(mCompleteIntent);
        }

    }

    private boolean isLoginFlow(AuthorizationManagementResponse response) {
        return response instanceof AuthorizationResponse;
    }

    private void runLoginFlow(AuthorizationResponse response, AuthorizationException ex) {

        if (mStateManager.getCurrent().isAuthorized()) {
            sendPendingIntent(mCompleteIntent);
            return;
        }

        if (response != null || ex != null) {
            mStateManager.updateAfterAuthorization(response, ex);
        }

        if (response != null && response.authorizationCode != null) {
            // authorization code exchange is required
            exchangeAuthorizationCode(response);
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
    }

    @Override
    protected void onSaveInstanceState(Bundle state) {
        state.putParcelable(KEY_COMPLETE_INTENT, mCompleteIntent);
        state.putParcelable(KEY_CANCEL_INTENT, mCancelIntent);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        mAuthService.dispose();
    }

    @MainThread
    private void signOut() {
        // discard the authorization and token state, but retain the configuration and
        // dynamic client registration (if applicable), to save from retrieving them again.
        AuthState currentState = mStateManager.getCurrent();
        AuthState clearedState =
                new AuthState(currentState.getAuthorizationServiceConfiguration());
        if (currentState.getLastRegistrationResponse() != null) {
            clearedState.update(currentState.getLastRegistrationResponse());
        }
        mStateManager.replace(clearedState);
        sendPendingIntent(mCancelIntent);
    }

    @MainThread
    private void exchangeAuthorizationCode(AuthorizationResponse authorizationResponse) {
        Log.d(TAG, "Exchanging authorization code");

        ClientAuthentication clientAuthentication;
        try {
            clientAuthentication = mStateManager.getCurrent().getClientAuthentication();
        } catch (ClientAuthentication.UnsupportedAuthenticationMethod ex) {
            Log.w(TAG, "Token request cannot be made, client authentication for the token "
                    + "endpoint could not be constructed (%s)", ex);
            return;
        }

        mAuthService.performTokenRequest(
                authorizationResponse.createTokenExchangeRequest(),
                clientAuthentication,
                new AuthorizationService.TokenResponseCallback() {
                    @Override
                    public void onTokenRequestCompleted(@Nullable TokenResponse response,
                            @Nullable AuthorizationException ex) {
                        handleCodeExchangeResponse(response, ex);
                    }
                });
    }

    @WorkerThread
    private void handleCodeExchangeResponse(
            @Nullable TokenResponse tokenResponse,
            @Nullable AuthorizationException authException) {

        mStateManager.updateAfterTokenResponse(tokenResponse, authException);
        if (!mStateManager.getCurrent().isAuthorized()) {
            final String message = "Authorization Code exchange failed"
                    + ((authException != null) ? authException.error : "");
            Log.e(TAG, message);
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    sendPendingIntent(mCancelIntent);
                }
            });
        } else {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    sendPendingIntent(mCompleteIntent);
                }
            });
        }
    }

    @VisibleForTesting
    void extractState(Bundle state) {
        if (state == null) {
            Logger.warn("No stored state - unable to handle response");
            finish();
            return;
        }
        mCompleteIntent = state.getParcelable(KEY_COMPLETE_INTENT);
        mCancelIntent = state.getParcelable(KEY_CANCEL_INTENT);
    }

    private void sendPendingIntent(PendingIntent pendingIntent) {
        try {
            pendingIntent.send();
        } catch (PendingIntent.CanceledException e) {
            Log.e(TAG, "Unable to send intent", e);
        }
        finish();
    }
}
