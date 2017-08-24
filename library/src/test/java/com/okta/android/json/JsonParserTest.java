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

package com.okta.android.json;

import android.net.Uri;

import com.okta.appauth.android.BuildConfig;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

@RunWith(RobolectricTestRunner.class)
@Config(constants = BuildConfig.class, sdk=16)
public class JsonParserTest {

    private static final String JSON_STRING =
            "{" +
            "  'hello': 'world'," +
            "  'empty': ''," +
            "  'http': 'http://example.com'," +
            "  'https': 'https://example.com'," +
            "  'queryUri': 'https://example.com?foo=bar'," +
            "  'fragmentUri': 'https://example.com#foo'," +
            "  'customUri': 'custom:/hello-world'," +
            "  'relativeUri': 'baz/qux'," +
            "  'email': 'leia@rebelalliance.io'," +
            "  'domain': 'x-wing://leia@rebelalliance.io'," +
            "  'stringList': [" +
            "    'foo'," +
            "    'bar'" +
            "  ]," +
            "  'emptyElementList': [" +
            "    ''" +
            "  ]," +
            "  'emptyList': [" +
            "  ]" +
            "}";

    /** * * * * * * * * * * * * * * * * * * * * * * * * * * * *
     *                                                        *
     * Tests for {@link JsonParser#getOptionalString(String)} *
     *                                                        *
     * * * * * * * * * * * * * * * * * * * * * * * * * * * * **/

    @Test
    public void testGetOptionalStringFindsString() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        assertThat(sut.getOptionalString("hello")).isEqualTo("world");
    }

    @Test
    public void testGetOptionalStringReturnsNullForMissingString() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        assertThat(sut.getOptionalString("missing")).isNull();
    }

    @Test
    public void testGetOptionalStringReturnsNullForEmptyString() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        assertThat(sut.getOptionalString("empty")).isNull();
    }

    @Test
    public void testGetRequiredStringFindsString() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        assertThat(sut.getRequiredString("hello")).isEqualTo("world");
    }

    @Test
    public void testGetRequiredStringThrowsForMissingString() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        try {
            sut.getRequiredString("missing");
            fail("Did not throw " + InvalidJsonDocumentException.class.getSimpleName());
        } catch (InvalidJsonDocumentException ex) {
            assertThat(ex.getMessage()).contains("missing");
        }
    }

    @Test
    public void testGetRequiredStringThrowsForEmptyString() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        try {
            sut.getRequiredString("empty");
            fail("Did not throw " + InvalidJsonDocumentException.class.getSimpleName());
        } catch (InvalidJsonDocumentException ex) {
            assertThat(ex.getMessage()).contains("empty");
        }
    }

    /** * * * * * * * * * * * * * * * * * * * * * * * * * * * *
     *                                                        *
     *   Tests for {@link JsonParser#getRequiredUri(String)}  *
     *                                                        *
     * * * * * * * * * * * * * * * * * * * * * * * * * * * * **/

    @Test
    public void testGetRequiredUriParsesHttpUri() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        assertThat(sut.getRequiredUri("http")).isEqualTo(Uri.parse("http://example.com"));
    }

    @Test
    public void testGetRequiredUriParsesHttpsUri() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        assertThat(sut.getRequiredUri("https")).isEqualTo(Uri.parse("https://example.com"));
    }

    @Test
    public void testGetRequiredUriThrowsForQueryParamUri() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        try {
            sut.getRequiredUri("queryUri");
            fail("Did not throw " + InvalidJsonDocumentException.class.getSimpleName());
        } catch (InvalidJsonDocumentException ex) {
            assertThat(ex.getMessage()).contains("queryUri");
        }
    }

    @Test
    public void testGetRequiredUriThrowsForFragmentUri() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        try {
            sut.getRequiredUri("fragmentUri");
            fail("Did not throw " + InvalidJsonDocumentException.class.getSimpleName());
        } catch (InvalidJsonDocumentException ex) {
            assertThat(ex.getMessage()).contains("fragmentUri");
        }
    }

    @Test
    public void testGetRequiredUriParsesCustomUri() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        assertThat(sut.getRequiredUri("customUri")).isEqualTo(Uri.parse("custom:/hello-world"));
    }

    @Test
    public void testGetRequiredUriThrowsForRelativeUri() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        try {
            sut.getRequiredUri("relativeUri");
            fail("Did not throw " + InvalidJsonDocumentException.class.getSimpleName());
        } catch (InvalidJsonDocumentException ex) {
            assertThat(ex.getMessage()).contains("relativeUri");
        }
    }

    @Test
    public void testGetRequiredUriThrowsForEmailUri() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        try {
            sut.getRequiredUri("email");
            fail("Did not throw " + InvalidJsonDocumentException.class.getSimpleName());
        } catch (InvalidJsonDocumentException ex) {
            assertThat(ex.getMessage()).contains("email");
        }
    }

    @Test
    public void testGetRequiredUriThrowsForDomainUri() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        try {
            sut.getRequiredUri("domain");
            fail("Did not throw " + InvalidJsonDocumentException.class.getSimpleName());
        } catch (InvalidJsonDocumentException ex) {
            assertThat(ex.getMessage()).contains("domain");
        }
    }

    @Test
    public void testGetRequiredUriThrowsForMissingString() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        try {
            sut.getRequiredUri("missing");
            fail("Did not throw " + InvalidJsonDocumentException.class.getSimpleName());
        } catch (InvalidJsonDocumentException ex) {
            assertThat(ex.getMessage()).contains("missing");
        }
    }

    @Test
    public void testGetRequiredUriThrowsForEmptyString() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        try {
            sut.getRequiredUri("empty");
            fail("Did not throw " + InvalidJsonDocumentException.class.getSimpleName());
        } catch (InvalidJsonDocumentException ex) {
            assertThat(ex.getMessage()).contains("empty");
        }
    }

    /** * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
     *                                                          *
     * Tests for {@link JsonParser#getRequiredHttpsUri(String)} *
     *                                                          *
     * * * * * * * * * * * * * * * * * * * * * * * * * * * * * **/

    @Test
    public void testGetRequiredHttpsUriParsesHttpUri() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        try {
            sut.getRequiredHttpsUri("http");
            fail("Did not throw " + InvalidJsonDocumentException.class.getSimpleName());
        } catch (InvalidJsonDocumentException ex) {
            assertThat(ex.getMessage()).contains("http");
        }
    }

    @Test
    public void testGetRequiredHttpsUriParsesHttpsUri() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        assertThat(sut.getRequiredHttpsUri("https")).isEqualTo(Uri.parse("https://example.com"));
    }

    @Test
    public void testGetRequiredHttpsUriThrowsForMissingString() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        try {
            sut.getRequiredHttpsUri("missing");
            fail("Did not throw " + InvalidJsonDocumentException.class.getSimpleName());
        } catch (InvalidJsonDocumentException ex) {
            assertThat(ex.getMessage()).contains("missing");
        }
    }

    @Test
    public void testGetRequiredHttpsUriThrowsForEmptyString() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        try {
            sut.getRequiredHttpsUri("empty");
            fail("Did not throw " + InvalidJsonDocumentException.class.getSimpleName());
        } catch (InvalidJsonDocumentException ex) {
            assertThat(ex.getMessage()).contains("empty");
        }
    }

    /** * * * * * * * * * * * * * * * * * * * * * * * * * * * * * **
     *                                                             *
     * Tests for {@link JsonParser#getRequiredStringArray(String)} *
     *                                                             *
     * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

    @Test
    public void testGetRequiredStringArrayParsesStringList() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        assertThat(sut.getRequiredStringArray("stringList")).containsExactly("foo", "bar");
    }

    @Test
    public void testGetRequiredStringArrayParsesEmptyStringList() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        try {
            sut.getRequiredStringArray("emptyElementList");
            fail("Did not throw " + InvalidJsonDocumentException.class.getSimpleName());
        } catch (InvalidJsonDocumentException ex) {
            assertThat(ex.getMessage()).contains("emptyElementList");
        }
    }

    @Test
    public void testGetRequiredStringArrayThrowsForNonArray() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        try {
            sut.getRequiredStringArray("hello");
            fail("Did not throw " + InvalidJsonDocumentException.class.getSimpleName());
        } catch (InvalidJsonDocumentException ex) {
            assertThat(ex.getMessage()).contains("hello");
        }
    }

    @Test
    public void testGetRequiredStringArrayThrowsForEmptyArray() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        try {
            sut.getRequiredStringArray("emptyList");
            fail("Did not throw " + InvalidJsonDocumentException.class.getSimpleName());
        } catch (InvalidJsonDocumentException ex) {
            assertThat(ex.getMessage()).contains("emptyList");
        }
    }

    @Test
    public void testGetRequiredStringArrayThrowsForMissingString() throws Exception {
        JsonParser sut = JsonParser.forJson(createJson());

        try {
            sut.getRequiredStringArray("missing");
            fail("Did not throw " + InvalidJsonDocumentException.class.getSimpleName());
        } catch (InvalidJsonDocumentException ex) {
            assertThat(ex.getMessage()).contains("missing");
        }
    }

    private JSONObject createJson() {
        JSONObject jsonObject;
        try {
            jsonObject = new JSONObject(JSON_STRING);
        } catch (JSONException e) {
            throw new IllegalStateException(e);
        }
        return jsonObject;
    }

}