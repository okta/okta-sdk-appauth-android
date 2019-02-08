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
import android.content.pm.ActivityInfo;
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

import com.okta.auth.AuthorizationCallback;
import com.okta.auth.OktaAuthManager;
import com.okta.auth.OktaAuthAccount;
import com.okta.auth.OktaClientAPI;
import com.okta.openid.appauth.AuthorizationException;
import com.okta.openid.appauth.AuthorizationResponse;
import com.okta.openid.appauth.TokenResponse;


import org.json.JSONObject;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Example Login Activity where authentication takes place.
 */
public class TestLoginActivity extends AppCompatActivity {

    private static final String TAG = "TestLoginActivity";
    private static final String EXTRA_FAILED = "failed";

    private OktaAuthManager mOktAuth;
    private OktaAuthAccount mOktaAccount;
    private OktaClientAPI mClient;
    private TextView mTvStatus;
    private Button mButton;
    private Button mSignOut;
    private AuthorizationResponse mResponse;
    private TokenResponse mToken;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Log.d(TAG, "onCreate");
        super.onCreate(savedInstanceState);
        setContentView(R.layout.test_activity_login);
        mButton = findViewById(R.id.start_button);
        mSignOut = findViewById(R.id.logout_button);
        mSignOut.setOnClickListener(v -> {
            if (mClient != null) {
                mOktAuth.logOut(this, new OktaClientAPI.RequestCallback<Boolean, AuthorizationException>() {
                    @Override
                    public void onSuccess(@NonNull Boolean result) {

                    }

                    @Override
                    public void onError(String error, AuthorizationException exception) {

                    }
                });
            }
        });


        mButton.setOnClickListener(v -> {
                    mOktAuth.startAuthorization(this, new AuthorizationCallback() {
                        @Override
                        public void onSuccess(OktaClientAPI clientAPI) {
                            Log.d("TestLoginActivity", "SUCCESS");
                            mClient = clientAPI;
                            mTvStatus.setText("authentication success");
                            mButton.setText("Get profile");
                            mButton.setOnClickListener(v -> getProfile());
                            mSignOut.setVisibility(View.VISIBLE);
                        }

                        @Override
                        public void onCancel() {
                            Log.d("TestLoginActivity", "CANCELED!");
                            mTvStatus.setText("canceled");
                        }

                        @Override
                        public void onError(String msg, AuthorizationException error) {
                            Log.d("TestLoginActivity", error.errorDescription + "onError" + Thread.currentThread().toString());
                            if (error != null) {
                                mTvStatus.setText(error.errorDescription);
                            } else {
                                mTvStatus.setText(msg);
                            }
                        }
                    });
                    //testing config change.
                    setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE);
                }
        );
        mTvStatus = findViewById(R.id.status);

        mOktaAccount = new OktaAuthAccount.Builder()
                .clientId("0oaiv94wtjW7DHvvj0h7")
                .redirectUri("com.okta.appauth.android.example:/callback")
                .endSessionRedirectUri("com.okta.appauth.android.example:/logout")
                .scopes("openid", "profile", "offline_access")
                .discoveryUri("https://dev-486177.oktapreview.com/oauth2/default")
                .create();

        mOktAuth = new OktaAuthManager.Builder()
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
        Log.d(TAG, "onActivityResult");
        super.onActivityResult(requestCode, resultCode, data);

        // Pass result to OktaAuthManager for processing
        mOktAuth.onActivityResult(requestCode, resultCode, data);
    }

    @Override
    protected void onDestroy() {
        Log.d(TAG, "onDestroy");
//        if (mOktAuth != null) {
//            mOktAuth.stop();
//        }
        if (mClient != null) {
            mClient.stop();
        }
        super.onDestroy();
    }


    @MainThread
    private void showSnackbar(String message) {
        Snackbar.make(findViewById(R.id.coordinator),
                message,
                Snackbar.LENGTH_SHORT)
                .show();
    }

    private ExecutorService mExecutor = Executors.newSingleThreadExecutor();

    private void getProfile() {
        mClient.getUserProfile(new OktaClientAPI.RequestCallback<JSONObject, AuthorizationException>() {
            @Override
            public void onSuccess(@NonNull JSONObject result) {
                mTvStatus.setText(result.toString());
            }

            @Override
            public void onError(String error, AuthorizationException exception) {
                Log.d(TAG, error, exception);
            }
        });

/*
        mExecutor.submit(() -> {
            try {
                JSONObject jsonObject = mClient.getUserProfile();
                runOnUiThread(() -> {
                    mTvStatus.setText(jsonObject.toString());
                });
            } catch (Exception ex) {
                Log.d(TAG, "", ex);
            }
        });
        */
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
