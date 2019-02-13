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

import android.content.Intent;
import android.os.Bundle;
import android.support.annotation.MainThread;
import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import com.okta.appauth.android.AuthenticationError;
import com.okta.appauth.android.OktaAppAuth;

import net.openid.appauth.AuthorizationException;

/**
 * Example Session Authorize Activity where authentication with session token takes place.
 */
public class SessionAuthorizeActivity extends AppCompatActivity {
    private static final String TAG = "SessionAuthActivity";

    private OktaAppAuth mOktaAppAuth;

    LinearLayout mContainer;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mOktaAppAuth = OktaAppAuth.getInstance(this);

        setContentView(R.layout.activity_session_login);

        findViewById(R.id.start_auth).setOnClickListener((View view) -> startAuth());

        mContainer = findViewById(R.id.auth_container);
    }

    @Override
    protected void onStart() {
        super.onStart();
        initializeOktaAuth();
    }

    @Override
    protected void onDestroy() {
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
                                startActivity(new Intent(SessionAuthorizeActivity.this,
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
                });
    }

    /**
     * Starts an authorization flow with the OktaAppAuth object. Make sure that the object is
     * initialized before this is called.
     * To get valid sessionToken you need to use
     * <a href="https://github.com/okta/okta-auth-java">okta-auth-java</a> library
     */
    @MainThread
    private void startAuth() {
        displayLoading(getString(R.string.loading_authorizing));

        String sessionToken = ((EditText)findViewById(R.id.session_token_value))
                .getText().toString();


        if (TextUtils.isEmpty(sessionToken)) {
            showMessage(getString(R.string.empty_login_or_password));
            return;
        }

        mOktaAppAuth.authenticate(sessionToken, new OktaAppAuth.OktaNativeAuthListener() {
            @Override
            public void onSuccess() {
                runOnUiThread(() -> {
                    startActivity(new Intent(getBaseContext(), UserInfoActivity.class));
                    finish();
                });
            }

            @Override
            public void onTokenFailure(@NonNull AuthenticationError ex) {
                runOnUiThread(() -> {
                    showMessage(ex.getMessage());
                    displayAuthOptions();
                });
            }
        });
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
}
