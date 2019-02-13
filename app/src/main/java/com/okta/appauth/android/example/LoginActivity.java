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

package com.okta.appauth.android.example;

import android.annotation.TargetApi;
import android.app.PendingIntent;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.ColorRes;
import android.support.annotation.MainThread;
import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import com.okta.appauth.android.OktaAppAuth;
import com.okta.appauth.android.OktaAppAuth.LoginHintChangeHandler;

import net.openid.appauth.AuthorizationException;

/**
 * Example Login Activity where authentication takes place.
 */
public class LoginActivity extends AppCompatActivity {
    private static final String TAG = "LoginActivity";
    private static final String EXTRA_FAILED = "failed";

    private OktaAppAuth mOktaAppAuth;

    LinearLayout mContainer;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mOktaAppAuth = OktaAppAuth.getInstance(this);

        setContentView(R.layout.activity_login);

        findViewById(R.id.start_auth).setOnClickListener((View view) -> startAuth());

        ((EditText) findViewById(R.id.login_hint_value)).addTextChangedListener(
                new LoginHintChangeHandler(mOktaAppAuth));

        mContainer = findViewById(R.id.auth_container);
    }

    @Override
    protected void onStart() {
        super.onStart();
        if (getIntent().getBooleanExtra(EXTRA_FAILED, false)) {
            showMessage(getString(R.string.auth_canceled));
        }

        initializeOktaAuth();
    }

    @Override
    protected void onDestroy() {
        if (mOktaAppAuth != null) {
            mOktaAppAuth.dispose();
            mOktaAppAuth = null;
        }
        super.onDestroy();
    }

    /**
     * Initializes the OktaAppAuth object. This is required before it can be used to authorize
     * users for your app.
     */
    @MainThread
    private void initializeOktaAuth() {
        Log.i(TAG, "Initializing OktaAppAuth");
        displayLoading(getString(R.string.loading_initializing));

        mOktaAppAuth.init(
                this,
                new OktaAppAuth.OktaAuthListener() {
                    @Override
                    public void onSuccess() {
                        runOnUiThread(() -> {
                            if (mOktaAppAuth.isUserLoggedIn()) {
                                Log.i(TAG, "User is already authenticated, proceeding " +
                                        "to token activity");
                                startActivity(new Intent(LoginActivity.this,
                                        UserInfoActivity.class));
                                finish();
                            } else {
                                Log.i(TAG, "Login activity setup finished");
                                displayAuthOptions();
                            }
                        });
                    }

                    @Override
                    public void onTokenFailure(@NonNull AuthorizationException ex) {
                        runOnUiThread(() -> showMessage(getString(R.string.init_failure)
                                + ":"
                                + ex.errorDescription));
                    }
                },
                getColorCompat(R.color.colorPrimary));
    }

    /**
     * Starts an authorization flow with the OktaAppAuth object. Make sure that the object is
     * initialized before this is called.
     */
    @MainThread
    private void startAuth() {
        displayLoading(getString(R.string.loading_authorizing));

        Intent completionIntent = new Intent(this, UserInfoActivity.class);
        Intent cancelIntent = new Intent(this, LoginActivity.class);
        cancelIntent.putExtra(EXTRA_FAILED, true);
        cancelIntent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);

        mOktaAppAuth.login(
                this,
                PendingIntent.getActivity(this, 0, completionIntent, 0),
                PendingIntent.getActivity(this, 0, cancelIntent, 0)
        );
    }

    @MainThread
    private void displayLoading(String loadingMessage) {
        findViewById(R.id.loading_container).setVisibility(View.VISIBLE);
        mContainer.setVisibility(View.GONE);

        ((TextView) findViewById(R.id.loading_description)).setText(loadingMessage);
    }

    @MainThread
    private void displayAuthOptions() {
        mContainer.setVisibility(View.VISIBLE);

        findViewById(R.id.loading_container).setVisibility(View.GONE);
    }

    @MainThread
    private void showMessage(String message) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show();
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
