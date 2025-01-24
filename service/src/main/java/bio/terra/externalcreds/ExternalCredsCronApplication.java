package bio.terra.externalcreds;

import bio.terra.common.logging.LoggingInitializer;
import bio.terra.externalcreds.services.PassportProviderService;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.ComponentScan.Filter;
import org.springframework.context.annotation.FilterType;
import org.springframework.scheduling.annotation.Scheduled;

@Slf4j
@SpringBootConfiguration
@EnableAutoConfiguration
@ComponentScan(
    basePackages = {
      "bio.terra.externalcreds",
      "bio.terra.common.logging",
      "bio.terra.common.retry.transaction",
      "bio.terra.common.tracing",
      "bio.terra.common.iam"
    },
    excludeFilters = @Filter(type = FilterType.ANNOTATION, classes = SpringBootConfiguration.class))
public class ExternalCredsCronApplication {

  public static void main(String[] args) {
    new SpringApplicationBuilder(ExternalCredsCronApplication.class)
        .initializers(new LoggingInitializer())
        .run(args);
  }

  private final PassportProviderService passportProviderService;

  public ExternalCredsCronApplication(PassportProviderService passportProviderService) {
    this.passportProviderService = passportProviderService;
  }

  @Scheduled(fixedRateString = "#{${externalcreds.background-job-interval-mins} * 60 * 1000}")
  public void checkForExpiringCredentials() {
    log.info("beginning check for expired linked accounts with passports");
    var expiredLinkedAccountCount =
        passportProviderService.invalidateExpiredLinkedAccountsWithPassports();
    log.info(
        "completed check for expired linked accounts with passports",
        Map.of("expired_linked_account_count", expiredLinkedAccountCount));

    // check and refresh expiring visas and passports
    log.info("beginning check for expiring passports and visas");
    var expiringPassportCount = passportProviderService.refreshExpiringPassports();
    log.info(
        "complete check for expiring passports and visas",
        Map.of("expiring_passport_count", expiringPassportCount));

    // check and validate visas not validated since job was last run
    log.info("beginning validateVisas");
    var checkedPassportCount = passportProviderService.validateAccessTokenVisas();
    log.info("completed validateVisas", Map.of("checked_passport_count", checkedPassportCount));
  }
}
