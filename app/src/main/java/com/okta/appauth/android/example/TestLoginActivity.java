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

package com.okta.appauth.android.example;

import android.annotation.TargetApi;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.ColorRes;
import android.support.annotation.MainThread;
import android.support.annotation.NonNull;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.okta.auth.AuthenticateClient;
import com.okta.auth.ResultCallback;
import com.okta.auth.AuthAccount;
import com.okta.auth.AuthorizeClient;
import com.okta.auth.RequestCallback;
import com.okta.openid.appauth.AuthorizationException;

import org.json.JSONObject;

/**
 * Example Login Activity where authentication takes place.
 */
public class TestLoginActivity extends AppCompatActivity {

    private static final String TAG = "TestLoginActivity";
    private static final String EXTRA_FAILED = "failed";

    private AuthenticateClient mOktaAuth;
    private AuthAccount mOktaAccount;
    private AuthorizeClient mClient;
    private TextView mTvStatus;
    private Button mButton;
    private Button mSignOut;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Log.d(TAG, "onCreate");
        super.onCreate(savedInstanceState);
        setContentView(R.layout.test_activity_login);
        mButton = findViewById(R.id.start_button);
        mSignOut = findViewById(R.id.logout_button);
        mSignOut.setOnClickListener(v -> {
            if (mClient != null) {
                mOktaAuth.logOut(new RequestCallback<Boolean, AuthorizationException>() {
                    @Override
                    public void onSuccess(@NonNull Boolean result) {
                        Log.d("TestLoginActivity", "Logout request success: " + result);
                    }

                    @Override
                    public void onError(String error, AuthorizationException exception) {
                        Log.d("TestLoginActivity", "Logout request error: " + error, exception);
                    }
                });
            }
        });

        mButton.setOnClickListener(v -> signIn());
        mTvStatus = findViewById(R.id.status);

        mOktaAccount = new AuthAccount.Builder()
                .clientId("0oaiv94wtjW7DHvvj0h7")
                .redirectUri("com.okta.appauth.android.example:/callback")
                .endSessionRedirectUri("com.okta.appauth.android.example:/logout")
                .scopes("openid", "profile", "offline_access")
                .discoveryUri("https://dev-486177.oktapreview.com/oauth2/default")
                .create();

        mOktaAuth = new AuthenticateClient.Builder(this)
                .withAccount(mOktaAccount)
                .withTabColor(getColorCompat(R.color.colorPrimary))
                .create();

    }

    @Override
    protected void onStart() {
        Log.d(TAG, "onStart");
        super.onStart();
        if (getIntent().getBooleanExtra(EXTRA_FAILED, false)) {
            showSnackbar(getString(R.string.auth_canceled));
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        Log.d(TAG, String.format("onActivityResult requestCode=%d resultCode=%d PID=%d", requestCode, resultCode, android.os.Process.myPid()));
        super.onActivityResult(requestCode, resultCode, data);

        // Pass result to AuthenticateClient for processing
        mOktaAuth.handleAuthResult(requestCode, resultCode, data, new ResultCallback<AuthorizeClient, AuthorizationException>() {
            @Override
            public void onSuccess(@NonNull AuthorizeClient clientAPI) {
                Log.d("TestLoginActivity", "SUCCESS");
                mClient = clientAPI;
                if (requestCode == AuthenticateClient.REQUEST_CODE_SIGN_OUT) {
                    mTvStatus.setText("sign out success");
                    mButton.setText("Sign In");
                    mButton.setOnClickListener(v -> signIn());
                    mSignOut.setVisibility(View.INVISIBLE);
                } else if (requestCode == AuthenticateClient.REQUEST_CODE_SIGN_IN) {
                    AuthorizeClient.AuthorizeAPI mClientAuthorizeAPI = clientAPI.getClientApi();
                    mTvStatus.setText("authentication success");
                    mButton.setText("Get profile");
                    mButton.setOnClickListener(v -> getProfile());
                    mSignOut.setVisibility(View.VISIBLE);
                }
            }

            @Override
            public void onCancel() {
                Log.d("TestLoginActivity", "CANCELED!");
                mTvStatus.setText("canceled");
            }

            @Override
            public void onError(@NonNull String msg, AuthorizationException error) {
                Log.d("TestLoginActivity", error.errorDescription + "onActivityResult onError " + msg, error);
                mTvStatus.setText(msg);
            }
        });
    }

    @MainThread
    private void showSnackbar(String message) {
        Snackbar.make(findViewById(R.id.coordinator),
                message,
                Snackbar.LENGTH_SHORT)
                .show();
    }

    private void signIn() {
        mOktaAuth.startAuthorization(new RequestCallback<Boolean, AuthorizationException>() {
            @Override
            public void onSuccess(Boolean success) {
                Log.d("TestLoginActivity", "request success: " + success);
            }

            @Override
            public void onError(String msg, AuthorizationException error) {
                Log.d("TestLoginActivity", msg + " " + error.errorDescription + " onError " + Thread.currentThread().toString());
                if (error != null) {
                    mTvStatus.setText(error.errorDescription);
                } else {
                    mTvStatus.setText(msg);
                }
            }
        });
        //testing config change.
        //setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE);
    }

    private void getProfile() {
        mClient.getUserProfile(new RequestCallback<JSONObject, AuthorizationException>() {
            @Override
            public void onSuccess(@NonNull JSONObject result) {
                mTvStatus.setText(result.toString());
            }

            @Override
            public void onError(String error, AuthorizationException exception) {
                Log.d(TAG, error, exception);
            }
        });
    }

    @TargetApi(Build.VERSION_CODES.M)
    @SuppressWarnings("deprecation")
    private int getColorCompat(@ColorRes int color) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return getColor(color);
        } else {
            return getResources().getColor(color);
        }
    }
}
