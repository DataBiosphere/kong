package bio.terra.externalcreds.config;

import java.time.Duration;
import org.immutables.value.Value;

@Value.Modifiable
@PropertiesInterfaceStyle
public interface NihCredentialsSyncConfigInterface {

  Duration getAllowlistValidityDuration();

  String getAllowlistManifestPath();

  String getGoogleProjectId();

  String getBucketName();

  boolean isFailClosed();
}
