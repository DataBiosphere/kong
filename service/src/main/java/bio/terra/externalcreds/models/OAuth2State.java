package bio.terra.externalcreds.models;

import bio.terra.externalcreds.ExternalCredsException;
import bio.terra.externalcreds.generated.model.Provider;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import org.immutables.value.Value;

@Value.Immutable
@JsonDeserialize(as = ImmutableOAuth2State.class)
public interface OAuth2State extends WithOAuth2State {
  Provider getProvider();

  String getRandom();

  String getRedirectUri();

  Optional<Map<String, String>> getAdditionalState();

  class Builder extends ImmutableOAuth2State.Builder {}

  default String encode(ObjectMapper objectMapper) {
    try {
      return new String(
          Base64.getEncoder()
              .encode(objectMapper.writeValueAsString(this).getBytes(StandardCharsets.UTF_8)),
          StandardCharsets.UTF_8);
    } catch (JsonProcessingException e) {
      throw new ExternalCredsException(e);
    }
  }

  static OAuth2State decode(ObjectMapper objectMapper, String encodedState)
      throws CannotDecodeOAuth2State {
    try {
      var decodedState = Base64.getDecoder().decode(encodedState);
      return objectMapper.readValue(decodedState, OAuth2State.class);
    } catch (Exception e) {
      throw new CannotDecodeOAuth2State(e);
    }
  }

  static String generateRandomState(SecureRandom secureRandom) {
    var randomStateBytes = new byte[50];
    secureRandom.nextBytes(randomStateBytes);
    return new String(Base64.getEncoder().encode(randomStateBytes), StandardCharsets.UTF_8);
  }
}
