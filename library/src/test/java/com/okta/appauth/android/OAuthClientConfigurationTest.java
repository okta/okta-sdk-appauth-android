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
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.ResolveInfo;
import android.net.Uri;

import com.okta.android.json.InvalidJsonDocumentException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.shadows.ShadowPackageManager;

import static com.okta.appauth.android.OAuthClientConfiguration.OIDC_DISCOVERY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.robolectric.Shadows.shadowOf;

@RunWith(RobolectricTestRunner.class)
public class OAuthClientConfigurationTest {

    private Context mContext;
    private SharedPreferences mPrefs;

    private OAuthClientConfiguration sut;

    @Before
    public void setUp() throws Exception {
        mContext = RuntimeEnvironment.application.getApplicationContext();
        mPrefs = RuntimeEnvironment.application
                .getSharedPreferences(OAuthClientConfiguration.PREFS_NAME, Context.MODE_PRIVATE);

        // Add resolve info for redirect URI since robolectric can't read it
        addResolveInfoForRedirectUri();

        sut = new OAuthClientConfiguration(
                mContext,
                mPrefs,
                ConfigurationStreams.getExampleConfiguration()
        );
    }

    private void addResolveInfoForRedirectUri() {
        Intent redirectIntent = new Intent();
        redirectIntent.setPackage(mContext.getPackageName());
        redirectIntent.setAction(Intent.ACTION_VIEW);
        redirectIntent.addCategory(Intent.CATEGORY_BROWSABLE);
        redirectIntent.setData(Uri.parse("com.okta.appauth.android.test:/oauth2redirect"));

        ShadowPackageManager packageManager = shadowOf(mContext.getPackageManager());
        ResolveInfo info = new ResolveInfo();
        info.isDefault = true;

        ApplicationInfo applicationInfo = new ApplicationInfo();
        applicationInfo.packageName = "com.example";
        info.activityInfo = new ActivityInfo();
        info.activityInfo.applicationInfo = applicationInfo;
        info.activityInfo.name = "Example";

        packageManager.addResolveInfoForIntent(redirectIntent, info);
    }

    @Test
    public void testGetInstanceUsesSameInstance() {
        assertThat(sut).isSameAs(OAuthClientConfiguration.getInstance(mContext));
        assertThat(sut.getConfigurationError()).isNull();
    }

    @Test
    public void testConfigurationHashChangesOnAccept() throws InvalidJsonDocumentException {
        assertThat(mPrefs.getString(OAuthClientConfiguration.KEY_LAST_HASH, null)).isNull();
        sut.acceptConfiguration();
        assertThat(mPrefs.getString(OAuthClientConfiguration.KEY_LAST_HASH, null)).isNotNull();

        sut = new OAuthClientConfiguration(
                mContext,
                mPrefs,
                ConfigurationStreams.getOtherConfiguration()
        );
        assertThat(sut.hasConfigurationChanged()).isTrue();
        sut.acceptConfiguration();
        assertThat(sut.hasConfigurationChanged()).isFalse();
    }

    @Test
    public void testConfigurationHashesJSONString() throws InvalidJsonDocumentException {
        sut = new OAuthClientConfiguration(
                mContext,
                mPrefs,
                ConfigurationStreams.getExampleConfiguration()
        );
        sut.acceptConfiguration();
        assertThat(sut.hasConfigurationChanged()).isFalse();
        sut.readConfiguration(sut.fetchConfiguration(ConfigurationStreams.getExampleConfiguration()));
        assertThat(sut.hasConfigurationChanged()).isFalse();
        sut.readConfiguration(sut.fetchConfiguration(ConfigurationStreams.getOtherConfiguration()));
        assertThat(sut.hasConfigurationChanged()).isTrue();
    }

    @Test
    public void testConfigurationIsInvalidForEmptyScopes() {
        sut = new OAuthClientConfiguration(
                mContext,
                mPrefs,
                ConfigurationStreams.getInvalidConfiguration()
        );
        assertThat(sut.isValid()).isFalse();
        assertThat(sut.getConfigurationError()).contains("scopes");
    }

    @Test
    public void testGetClientId() {
        assertThat(sut.getClientId()).isEqualTo("example_client_id");
    }

    @Test
    public void getRedirectUri() {
        assertThat(sut.getRedirectUri()).isEqualTo(
                Uri.parse("com.okta.appauth.android.test:/oauth2redirect"));
    }

    @Test
    public void testGetDiscoveryUriAppendsWellKnownDiscovery() {
        assertThat(sut.getDiscoveryUri()).isEqualTo(
                Uri.parse("https://example.com/issuer/" + OIDC_DISCOVERY)
        );
    }

    @Test
    public void testGetScopes() {
        assertThat(sut.getScopes()).contains("openid", "foo");
    }
}