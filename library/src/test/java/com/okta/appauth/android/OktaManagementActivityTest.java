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

import android.app.PendingIntent;
import android.app.PendingIntent.CanceledException;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;

import net.openid.appauth.AuthState;
import net.openid.appauth.AuthorizationResponse;
import org.assertj.android.api.Assertions;
import org.json.JSONException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;

import static android.content.Context.MODE_PRIVATE;

import static com.okta.appauth.android.OktaManagementActivity.KEY_CANCEL_INTENT;
import static com.okta.appauth.android.OktaManagementActivity.KEY_COMPLETE_INTENT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
public class OktaManagementActivityTest {

    @Mock PendingIntent mCompleteIntent;
    @Mock PendingIntent mCancelIntent;

    @Spy AuthState mAuthState;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        Context context = RuntimeEnvironment.application.getApplicationContext();
        new OAuthClientConfiguration(
                context,
                context.getSharedPreferences(OAuthClientConfiguration.PREFS_NAME, MODE_PRIVATE),
                ConfigurationStreams.getExampleConfiguration()
        ).acceptConfiguration();
    }

    @Test
    public void testOnCreateShouldFinishWhenNoStatePassed() {
        OktaManagementActivity activity = Robolectric.buildActivity(
                OktaManagementActivity.class
        ).create().get();

        assertThat(activity.isFinishing()).isTrue();
    }

    @Test
    public void testOnCreateShouldExtractStateFromIntent() throws JSONException {
        OktaManagementActivity activity = Robolectric.buildActivity(
                OktaManagementActivity.class,
                createStartIntent()
        ).create().get();

        assertThat(activity.mCompleteIntent).isEqualTo(this.mCompleteIntent);
        assertThat(activity.mCancelIntent).isEqualTo(this.mCancelIntent);
    }

    @Test
    public void testOnCreateShouldExtractStateFromSavedInstanceState() {
        OktaManagementActivity activity = Robolectric.buildActivity(
                OktaManagementActivity.class
        ).create(createStartBundle()).get();

        assertThat(activity.mCompleteIntent).isEqualTo(this.mCompleteIntent);
        assertThat(activity.mCancelIntent).isEqualTo(this.mCancelIntent);
    }

    @Test
    public void testOnSaveInstanceStateWritesToTheBundle() throws JSONException {
        Bundle bundle = new Bundle();

        OktaManagementActivity activity = Robolectric.buildActivity(
                OktaManagementActivity.class,
                createStartIntent()
        ).create().saveInstanceState(bundle).get();

        Assertions.assertThat(bundle).hasKey(KEY_COMPLETE_INTENT);
        Assertions.assertThat(bundle).hasKey(KEY_CANCEL_INTENT);

        activity.extractState(bundle);

        assertThat(activity.mCompleteIntent).isEqualTo(this.mCompleteIntent);
        assertThat(activity.mCancelIntent).isEqualTo(this.mCancelIntent);
    }

    @Test
    public void testOnStartShouldSignOutIfConfigurationHasChanged() throws CanceledException, JSONException {
        // Create new configuration to change the hash
        Context context = RuntimeEnvironment.application.getApplicationContext();
        new OAuthClientConfiguration(
                context,
                context.getSharedPreferences(OAuthClientConfiguration.PREFS_NAME, MODE_PRIVATE),
                ConfigurationStreams.getOtherConfiguration()
        );

        doNothing().when(mCancelIntent).send();

        OktaManagementActivity activity = Robolectric.buildActivity(
                OktaManagementActivity.class
        ).newIntent(createStartIntent()).create().start().get();

        assertThat(activity.isFinishing()).isTrue();
    }

    @Test
    public void testOnStartShouldCompleteIfStateIsAuthorized() throws CanceledException, JSONException {
        Context context = RuntimeEnvironment.application.getApplicationContext();
        AuthStateManager stateManager = AuthStateManager.getInstance(context);
        stateManager.replace(mAuthState);

        when(mAuthState.isAuthorized()).thenReturn(true);
        doNothing().when(mCompleteIntent).send();

        OktaManagementActivity activity = Robolectric.buildActivity(
                OktaManagementActivity.class,
                createStartIntent()
        ).create().start().get();

        assertThat(activity.isFinishing()).isTrue();
    }

    private Intent createStartIntent() throws JSONException {
        Intent tokenExchangeIntent = new Intent(
                RuntimeEnvironment.application.getApplicationContext(),
                OktaManagementActivity.class);
        tokenExchangeIntent.putExtra(AuthorizationResponse.EXTRA_RESPONSE, ConfigurationStreams.VALID_AUTHORIZATION_RESPONSE);
        tokenExchangeIntent.putExtra(KEY_COMPLETE_INTENT, mCompleteIntent);
        tokenExchangeIntent.putExtra(KEY_CANCEL_INTENT, mCancelIntent);

        return tokenExchangeIntent;
    }

    private Bundle createStartBundle() {
        Bundle bundle = new Bundle();
        bundle.putParcelable(KEY_COMPLETE_INTENT, mCompleteIntent);
        bundle.putParcelable(KEY_CANCEL_INTENT, mCancelIntent);
        return bundle;
    }
}