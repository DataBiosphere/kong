package scripts.testscripts;

import static org.junit.jupiter.api.Assertions.assertEquals;

import bio.terra.externalcreds.api.SshKeyPairApi;
import bio.terra.externalcreds.model.SshKeyPair;
import bio.terra.externalcreds.model.SshKeyPairType;
import bio.terra.testrunner.runner.TestScript;
import bio.terra.testrunner.runner.config.TestUserSpecification;
import com.google.api.client.http.HttpStatusCodes;
import lombok.extern.slf4j.Slf4j;
import scripts.utils.ClientTestUtils;

@Slf4j
public class StoreSshKeyPair extends TestScript {
  private static final String SSH_PRIVATE_KEY =
      "-----BEGIN OPENSSH PRIVATE KEY-----\n"
          + "abcde12345/+xXXXYZ//890=\n"
          + "-----END OPENSSH PRIVATE KEY-----";
  private static final String SSH_PUBLIC_KEY =
      "ssh-ed25519 AAABBBccc123 foo@monkeyseesmonkeydo.com";
  private static final String EXTERNAL_USER_EMAIL = "foo@monkeyseesmonkeydo.com";

  @Override
  public void userJourney(TestUserSpecification testUser) throws Exception {
    var apiClient = ClientTestUtils.getClientWithTestUserAuth(testUser, server);
    var sshKeyPairApi = new SshKeyPairApi(apiClient);
    var sshKeyPair =
        new SshKeyPair()
            .externalUserEmail(EXTERNAL_USER_EMAIL)
            .privateKey(SSH_PRIVATE_KEY)
            .publicKey(SSH_PUBLIC_KEY);
    sshKeyPairApi.putSshKeyPair(SshKeyPairType.GITHUB, sshKeyPair);
    var httpCodeForPut = sshKeyPairApi.getApiClient().getStatusCode();
    assertEquals(HttpStatusCodes.STATUS_CODE_OK, httpCodeForPut);

    var getResult = sshKeyPairApi.getSshKeyPair(SshKeyPairType.GITHUB);
    assertEquals(sshKeyPair, getResult);
    var httpCodeForGet = sshKeyPairApi.getApiClient().getStatusCode();
    assertEquals(HttpStatusCodes.STATUS_CODE_OK, httpCodeForGet);

    sshKeyPairApi.deleteSshKeyPair(SshKeyPairType.GITHUB);
    var httpCodeForDelete = sshKeyPairApi.getApiClient().getStatusCode();
    assertEquals(HttpStatusCodes.STATUS_CODE_OK, httpCodeForDelete);

    sshKeyPairApi.getSshKeyPair(SshKeyPairType.GITHUB);
    var httpCodeForGetEmpty = sshKeyPairApi.getApiClient().getStatusCode();
    assertEquals(HttpStatusCodes.STATUS_CODE_NOT_FOUND, httpCodeForGet);
  }
}
