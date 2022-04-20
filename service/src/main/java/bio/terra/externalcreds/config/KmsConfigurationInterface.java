package bio.terra.externalcreds.config;

import java.time.Duration;
import org.immutables.value.Value;

@Value.Modifiable
@PropertiesInterfaceStyle
public interface KmsConfigurationInterface {
  String getServiceGoogleProject();

  String getKeyRingId();

  String getKeyId();

  String getKeyRingLocation();

  @Value.Default
  default Duration getSshKeyPairRefreshDuration() {
    return Duration.ofDays(90);
  }
}
