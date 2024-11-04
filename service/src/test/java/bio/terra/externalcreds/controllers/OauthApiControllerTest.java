package bio.terra.externalcreds.controllers;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import bio.terra.common.exception.BadRequestException;
import bio.terra.common.exception.NotFoundException;
import bio.terra.common.iam.BearerToken;
import bio.terra.common.iam.SamUser;
import bio.terra.externalcreds.BaseTest;
import bio.terra.externalcreds.ExternalCredsException;
import bio.terra.externalcreds.TestUtils;
import bio.terra.externalcreds.auditLogging.AuditLogEvent;
import bio.terra.externalcreds.auditLogging.AuditLogEventType;
import bio.terra.externalcreds.auditLogging.AuditLogger;
import bio.terra.externalcreds.generated.model.LinkInfo;
import bio.terra.externalcreds.generated.model.Provider;
import bio.terra.externalcreds.models.LinkedAccount;
import bio.terra.externalcreds.models.LinkedAccountWithPassportAndVisas;
import bio.terra.externalcreds.models.OAuth2State;
import bio.terra.externalcreds.services.FenceProviderService;
import bio.terra.externalcreds.services.LinkedAccountService;
import bio.terra.externalcreds.services.PassportProviderService;
import bio.terra.externalcreds.services.ProviderService;
import bio.terra.externalcreds.services.TokenProviderService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.LinkedMultiValueMap;

@AutoConfigureMockMvc
class OauthApiControllerTest extends BaseTest {
  @Autowired private ObjectMapper mapper;

  @Autowired private MockMvc mvc;

  @MockBean private LinkedAccountService linkedAccountServiceMock;

  @MockBean
  @Qualifier("providerService")
  private ProviderService providerServiceMock;

  @MockBean
  @Qualifier("passportProviderService")
  private PassportProviderService passportProviderServiceMock;

  @MockBean
  @Qualifier("tokenProviderService")
  private TokenProviderService tokenProviderServiceMock;

  @MockBean
  @Qualifier("fenceProviderService")
  private FenceProviderService fenceProviderServiceMock;

  @MockBean private ExternalCredsSamUserFactory samUserFactoryMock;
  @MockBean private AuditLogger auditLoggerMock;

  private Provider provider = Provider.RAS;

  @Test
  void testListProviders() throws Exception {
    when(providerServiceMock.getProviderList())
        .thenReturn(Set.of("fake-provider2", "fake-provider1"));

    mvc.perform(get("/api/oidc/v1/providers"))
        .andExpect(content().json("""
            ["fake-provider1","fake-provider2"]"""));
  }

  @Nested
  class GetLink {

    @Test
    void testGetLink() throws Exception {
      var accessToken = "testToken";
      var inputLinkedAccount = TestUtils.createRandomLinkedAccount();

      mockSamUser(inputLinkedAccount.getUserId(), accessToken);

      when(linkedAccountServiceMock.getLinkedAccount(
              inputLinkedAccount.getUserId(), inputLinkedAccount.getProvider()))
          .thenReturn(Optional.of(inputLinkedAccount));

      mvc.perform(
              get("/api/oauth/v1/" + inputLinkedAccount.getProvider().toString())
                  .header("authorization", "Bearer " + accessToken))
          .andExpect(
              content()
                  .json(
                      mapper.writeValueAsString(
                          OpenApiConverters.Output.convert(inputLinkedAccount))));
    }

    @Test
    void testGetFenceLink() throws Exception {
      var accessToken = "testToken";
      var inputLinkedAccount = TestUtils.createRandomLinkedAccount(Provider.FENCE);

      mockSamUser(inputLinkedAccount.getUserId(), accessToken);

      when(linkedAccountServiceMock.getLinkedAccount(
              inputLinkedAccount.getUserId(), inputLinkedAccount.getProvider()))
          .thenReturn(Optional.of(inputLinkedAccount));

      mvc.perform(
              get("/api/oauth/v1/" + inputLinkedAccount.getProvider().toString())
                  .header("authorization", "Bearer " + accessToken))
          .andExpect(
              content()
                  .json(
                      mapper.writeValueAsString(
                          OpenApiConverters.Output.convert(inputLinkedAccount))));
    }

    @Test
    void testEnforcesCaseSensitivity() throws Exception {
      var accessToken = "testToken";
      var inputLinkedAccount = TestUtils.createRandomPassportLinkedAccount();

      mockSamUser(inputLinkedAccount.getUserId(), accessToken);

      when(linkedAccountServiceMock.getLinkedAccount(
              inputLinkedAccount.getUserId(), inputLinkedAccount.getProvider()))
          .thenReturn(Optional.of(inputLinkedAccount));

      mvc.perform(get("/api/oauth/v1/" + "RaS").header("authorization", "Bearer " + accessToken))
          .andExpect(
              content()
                  .json(
                      mapper.writeValueAsString(
                          OpenApiConverters.Output.convert(inputLinkedAccount))));
    }

    @Test
    void testGetLink404() throws Exception {
      var userId = "non-existent-user";
      var accessToken = "testToken";

      mockSamUser(userId, accessToken);

      mvc.perform(get("/api/oauth/v1/" + provider).header("authorization", "Bearer " + accessToken))
          .andExpect(status().isNotFound());
    }
  }

  @Nested
  class CreateLink {

    @Test
    void testCreatesTokenProviderLinkSuccessfully() throws Exception {
      var inputLinkedAccount = TestUtils.createRandomLinkedAccount(Provider.GITHUB);

      var state = UUID.randomUUID().toString();
      var oauthcode = UUID.randomUUID().toString();

      when(tokenProviderServiceMock.createLink(
              eq(inputLinkedAccount.getProvider()),
              eq(inputLinkedAccount.getUserId()),
              eq(oauthcode),
              eq(state),
              any(AuditLogEvent.Builder.class)))
          .thenReturn(inputLinkedAccount);
      testCreatesLinkSuccessfully(inputLinkedAccount, state, oauthcode, false);
    }

    @Test
    void testCreatesPassportProviderLinkSuccessfully() throws Exception {
      var inputLinkedAccount = TestUtils.createRandomPassportLinkedAccount();
      var state = UUID.randomUUID().toString();
      var oauthcode = UUID.randomUUID().toString();

      var linkedAccountWithPassportAndVisas =
          new LinkedAccountWithPassportAndVisas.Builder()
              .linkedAccount(inputLinkedAccount)
              .passport(TestUtils.createRandomPassport())
              .build();
      when(passportProviderServiceMock.createLink(
              eq(inputLinkedAccount.getProvider()),
              eq(inputLinkedAccount.getUserId()),
              eq(oauthcode),
              eq(state),
              any(AuditLogEvent.Builder.class)))
          .thenReturn(linkedAccountWithPassportAndVisas);

      testCreatesLinkSuccessfully(inputLinkedAccount, state, oauthcode, false);
    }

    @Test
    void testCreateFenceLink() throws Exception {
      var inputLinkedAccount = TestUtils.createRandomLinkedAccount(Provider.FENCE);

      var state = UUID.randomUUID().toString();
      var oauthcode = UUID.randomUUID().toString();

      when(fenceProviderServiceMock.createLink(
              eq(inputLinkedAccount.getProvider()),
              eq(inputLinkedAccount.getUserId()),
              eq(oauthcode),
              eq(state),
              any(AuditLogEvent.Builder.class)))
          .thenReturn(inputLinkedAccount);
      testCreatesLinkSuccessfully(inputLinkedAccount, state, oauthcode, false);
    }

    @Test
    void testCreateLinkReturnsAdditionalState() throws Exception {
      var inputLinkedAccount = TestUtils.createRandomLinkedAccount(Provider.GITHUB);
      var oauthcode = UUID.randomUUID().toString();
      Map<String, String> additionalStateParam = new HashMap<>();
      additionalStateParam.put("redirectTo", "http://foo.org");
      String redirectUri = "https://foo.bar.com";
      OAuth2State oAuth2State =
          new OAuth2State.Builder()
              .provider(Provider.GITHUB)
              .random(UUID.randomUUID().toString())
              .redirectUri(redirectUri)
              .additionalState(additionalStateParam)
              .build();
      var state = oAuth2State.encode(mapper);
      when(providerServiceMock.getAdditionalStateParams(state))
          .thenReturn(Optional.of(additionalStateParam));

      when(tokenProviderServiceMock.createLink(
              eq(inputLinkedAccount.getProvider()),
              eq(inputLinkedAccount.getUserId()),
              eq(oauthcode),
              eq(state),
              any(AuditLogEvent.Builder.class)))
          .thenReturn(inputLinkedAccount);
      testCreatesLinkSuccessfully(inputLinkedAccount, state, oauthcode, true);
    }

    @Test
    void testExceptionIsLogged() throws Exception {
      var accessToken = "testToken";

      var userId = "userId";
      mockSamUser(userId, accessToken);

      when(passportProviderServiceMock.createLink(any(), any(), any(), any(), any()))
          .thenThrow(new ExternalCredsException("This is a drill!"));

      // check that an internal server error code is returned
      mvc.perform(
              post("/api/oauth/v1/{provider}/oauthcode", provider)
                  .header("authorization", "Bearer " + accessToken)
                  .param("scopes", "foo")
                  .param("redirectUri", "redirectUri")
                  .param("state", "state")
                  .param("oauthcode", "oauthcode"))
          .andExpect(status().isInternalServerError());

      // check that a log was recorded
      verify(auditLoggerMock)
          .logEvent(
              new AuditLogEvent.Builder()
                  .auditLogEventType(AuditLogEventType.LinkCreationFailed)
                  .provider(provider)
                  .userId(userId)
                  .clientIP("127.0.0.1")
                  .build());
    }
  }

  @Nested
  class DeleteLink {

    @Test
    void testDeleteLink() throws Exception {
      var accessToken = "testToken";
      var userId = UUID.randomUUID().toString();
      var externalId = UUID.randomUUID().toString();
      mockSamUser(userId, accessToken);

      when(providerServiceMock.deleteLink(userId, provider))
          .thenReturn(
              new LinkedAccount.Builder()
                  .provider(provider)
                  .userId(userId)
                  .externalUserId(externalId)
                  .expires(new Timestamp(0))
                  .isAuthenticated(true)
                  .refreshToken("")
                  .build());

      mvc.perform(
              delete("/api/oauth/v1/{provider}", provider)
                  .header("authorization", "Bearer " + accessToken))
          .andExpect(status().isOk());

      verify(providerServiceMock).deleteLink(userId, provider);

      // check that a log was recorded
      verify(auditLoggerMock)
          .logEvent(
              new AuditLogEvent.Builder()
                  .auditLogEventType(AuditLogEventType.LinkDeleted)
                  .provider(provider)
                  .userId(userId)
                  .clientIP("127.0.0.1")
                  .externalUserId(externalId)
                  .build());
    }

    @Test
    void testDeleteLink404() throws Exception {
      var accessToken = "testToken";
      var userId = UUID.randomUUID().toString();
      mockSamUser(userId, accessToken);

      doThrow(new NotFoundException("not found"))
          .when(providerServiceMock)
          .deleteLink(userId, provider);

      mvc.perform(
              delete("/api/oauth/v1/{provider}", provider)
                  .header("authorization", "Bearer " + accessToken))
          .andExpect(status().isNotFound());
    }

    @Test
    void testDeleteLinkFence() throws Exception {
      var accessToken = "testToken";
      var userId = UUID.randomUUID().toString();
      var externalId = UUID.randomUUID().toString();
      mockSamUser(userId, accessToken);

      when(providerServiceMock.deleteLink(userId, Provider.FENCE))
          .thenReturn(
              new LinkedAccount.Builder()
                  .provider(Provider.FENCE)
                  .userId(userId)
                  .externalUserId(externalId)
                  .expires(new Timestamp(0))
                  .isAuthenticated(true)
                  .refreshToken("")
                  .build());

      mvc.perform(
              delete("/api/oauth/v1/{provider}", Provider.FENCE)
                  .header("authorization", "Bearer " + accessToken))
          .andExpect(status().isOk());

      verify(providerServiceMock).deleteLink(userId, Provider.FENCE);

      // check that a log was recorded
      verify(auditLoggerMock)
          .logEvent(
              new AuditLogEvent.Builder()
                  .auditLogEventType(AuditLogEventType.LinkDeleted)
                  .provider(Provider.FENCE)
                  .userId(userId)
                  .clientIP("127.0.0.1")
                  .externalUserId(externalId)
                  .build());
    }
  }

  @Nested
  class GetAuthUrl {

    @Test
    void testGetAuthUrl() throws Exception {
      var userId = "fakeUser";
      var accessToken = "fakeAccessToken";
      var result = "https://test/authorization/uri";
      var redirectUri = "fakeuri";

      mockSamUser(userId, accessToken);

      when(providerServiceMock.getProviderAuthorizationUrl(userId, provider, redirectUri, null))
          .thenReturn(result);

      var queryParams = new LinkedMultiValueMap<String, String>();
      queryParams.add("redirectUri", redirectUri);
      mvc.perform(
              get("/api/oauth/v1/{provider}/authorization-url", provider)
                  .header("authorization", "Bearer " + accessToken)
                  .queryParams(queryParams))
          .andExpect(content().string(result));
    }

    @Test
    void testGetAuthUrlWithAdditionalState() throws Exception {
      var userId = "fakeUser";
      var accessToken = "fakeAccessToken";
      var result = "https://test/authorization/uri";
      var redirectUri = "fakeuri";
      Map<String, String> additionalStateParam = new HashMap<>();
      additionalStateParam.put("redirectTo", "http://foo.org");

      mockSamUser(userId, accessToken);

      when(providerServiceMock.getProviderAuthorizationUrl(
              userId, provider, redirectUri, additionalStateParam))
          .thenReturn(result);

      var queryParams = new LinkedMultiValueMap<String, String>();
      queryParams.add("redirectUri", redirectUri);
      mvc.perform(
              post("/api/oauth/v1/{provider}/authorization-url", provider)
                  .header("authorization", "Bearer " + accessToken)
                  .queryParams(queryParams)
                  .contentType(MediaType.APPLICATION_JSON)
                  .content(mapper.writeValueAsString(additionalStateParam)))
          .andExpect(content().string(result));
    }

    @Test
    void testGetAuthUrlBadRequest() throws Exception {
      var userId = "fakeUser";
      var accessToken = "fakeAccessToken";
      var redirectUri = "fakeuri";

      mockSamUser(userId, accessToken);

      when(providerServiceMock.getProviderAuthorizationUrl(userId, provider, redirectUri, null))
          .thenThrow(new BadRequestException("Invalid redirectUri"));

      var queryParams = new LinkedMultiValueMap<String, String>();
      queryParams.add("redirectUri", redirectUri);
      mvc.perform(
              get("/api/oauth/v1/{provider}/authorization-url", provider)
                  .header("authorization", "Bearer " + accessToken)
                  .queryParams(queryParams))
          .andExpect(status().isBadRequest());
    }
  }

  @Nested
  class GetProviderAccessToken {

    @Test
    void testGetProviderAccessToken() throws Exception {
      var userId = "fakeUser";
      var accessToken = "fakeAccessToken";
      var githubAccessToken = "fakeGithubAccessToken";
      var provider = Provider.GITHUB;
      mockSamUser(userId, accessToken);

      when(tokenProviderServiceMock.getProviderAccessToken(any(), eq(provider), any()))
          .thenReturn(githubAccessToken);

      mvc.perform(
              get("/api/oauth/v1/{provider}/access-token", provider)
                  .header("authorization", "Bearer " + accessToken))
          .andExpect(status().isOk())
          .andExpect(content().string(githubAccessToken));
    }

    @Test
    void testGetProviderAccessToken404() throws Exception {
      var userId = "fakeUser";
      var accessToken = "fakeAccessToken";
      var provider = Provider.GITHUB;
      mockSamUser(userId, accessToken);

      when(tokenProviderServiceMock.getProviderAccessToken(any(), eq(provider), any()))
          .thenThrow(new NotFoundException("not found"));

      mvc.perform(
              get("/api/oauth/v1/{provider}/access-token", provider)
                  .header("authorization", "Bearer " + accessToken))
          .andExpect(status().isNotFound());
    }
  }

  private void testCreatesLinkSuccessfully(
      LinkedAccount inputLinkedAccount, String state, String oauthcode, boolean decodeState)
      throws Exception {
    var accessToken = "testToken";
    mockSamUser(inputLinkedAccount.getUserId(), accessToken);
    LinkInfo linkInfo = OpenApiConverters.Output.convert(inputLinkedAccount);
    if (decodeState) {
      OAuth2State decodedState = OAuth2State.decode(mapper, state);
      linkInfo.additionalState(decodedState.getAdditionalState().get());
    }

    mvc.perform(
            post("/api/oauth/v1/{provider}/oauthcode", inputLinkedAccount.getProvider())
                .header("authorization", "Bearer " + accessToken)
                .param("state", state)
                .param("oauthcode", oauthcode))
        .andExpect(status().isOk())
        .andExpect(content().json(mapper.writeValueAsString(linkInfo)));
  }

  private void mockSamUser(String userId, String accessToken) {
    when(samUserFactoryMock.from(any(HttpServletRequest.class)))
        .thenReturn(new SamUser("email", userId, new BearerToken(accessToken)));
  }
}
