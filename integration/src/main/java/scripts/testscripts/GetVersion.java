package scripts.testscripts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import bio.terra.externalcreds.api.PublicApi;
import bio.terra.testrunner.runner.TestScript;
import bio.terra.testrunner.runner.config.TestUserSpecification;
import com.google.api.client.http.HttpStatusCodes;
import lombok.extern.slf4j.Slf4j;
import scripts.utils.ClientTestUtils;

@Slf4j
public class GetVersion extends TestScript {

  @Override
  public void userJourney(TestUserSpecification testUser) throws Exception {
    log.info("Checking the version endpoint.");
    var apiClient = ClientTestUtils.getClientWithoutAccessToken(server);
    var publicApi = new PublicApi(apiClient);

    var versionProperties = publicApi.getVersion();

    // check the response code
    var httpCode = publicApi.getApiClient().getStatusCode();
    assertEquals(HttpStatusCodes.STATUS_CODE_OK, httpCode);
    log.info("Service status return code: {}", httpCode);

    // check the response body
    assertNotNull(versionProperties);
    assertNotNull(versionProperties.getGitHash());
    assertNotNull(versionProperties.getGitTag());
    assertNotNull(versionProperties.getGithub());
    assertNotNull(versionProperties.getBuild());
  }
}
