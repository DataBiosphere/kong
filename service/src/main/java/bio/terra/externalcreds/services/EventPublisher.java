package bio.terra.externalcreds.services;

import bio.terra.externalcreds.ExternalCredsException;
import bio.terra.externalcreds.config.ExternalCredsConfig;
import bio.terra.externalcreds.models.AuthorizationChangeEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.core.ApiFutureCallback;
import com.google.api.core.ApiFutures;
import com.google.api.gax.rpc.ApiException;
import com.google.cloud.pubsub.v1.Publisher;
import com.google.cloud.pubsub.v1.TopicAdminClient;
import com.google.cloud.pubsub.v1.TopicAdminSettings;
import com.google.common.util.concurrent.MoreExecutors;
import com.google.protobuf.ByteString;
import com.google.pubsub.v1.PubsubMessage;
import jakarta.annotation.PreDestroy;
import java.io.IOException;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class EventPublisher {

  private final ObjectMapper objectMapper;
  private final Optional<Publisher> authorizationChangeEventPublisher;

  public EventPublisher(ExternalCredsConfig externalCredsConfig, ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;

    // note that Publisher authenticates to Google using the env var GOOGLE_APPLICATION_CREDENTIALS
    // the Publisher will be disabled when running locally, to prevent tests from using it
    if (externalCredsConfig.getAuthorizationChangeEventsEnabled()) {
      this.authorizationChangeEventPublisher =
          externalCredsConfig
              .getAuthorizationChangeEventTopicName()
              .map(
                  topicName -> {
                    try {
                      return Publisher.newBuilder(topicName).build();
                    } catch (IOException e) {
                      throw new ExternalCredsException("exception building event publisher", e);
                    }
                  });
    } else {
      this.authorizationChangeEventPublisher = Optional.empty();
    }
  }

  public void publishAuthorizationChangeEvent(AuthorizationChangeEvent event) {
    authorizationChangeEventPublisher.ifPresent(
        publisher -> {
          try {
            try (TopicAdminClient topicAdminClient =
                TopicAdminClient.create(TopicAdminSettings.newBuilder().build())) {
              try {
                topicAdminClient.getTopic(publisher.getTopicName());
              } catch (ApiException e) {
                log.info("creating new topic: {}", publisher.getTopicName());
                topicAdminClient.createTopic(publisher.getTopicName());
              }
            } catch (IOException e) {
              throw new ExternalCredsException("exception building event publisher", e);
            }
            var message =
                PubsubMessage.newBuilder()
                    .setData(ByteString.copyFromUtf8(objectMapper.writeValueAsString(event)))
                    .build();
            var apiFuture = publisher.publish(message);
            ApiFutures.addCallback(
                apiFuture,
                new ApiFutureCallback<>() {
                  @Override
                  public void onFailure(Throwable throwable) {
                    log.error("failure publishing authorization change event", throwable);
                  }

                  @Override
                  public void onSuccess(String messageId) {}
                },
                MoreExecutors.directExecutor());
          } catch (JsonProcessingException e) {
            throw new ExternalCredsException(
                "json exception writing authorization change event:" + event, e);
          }
        });
  }

  @PreDestroy
  void shutdownPublisher() {
    authorizationChangeEventPublisher.ifPresent(
        publisher -> {
          try {
            publisher.shutdown();
            publisher.awaitTermination(1, TimeUnit.MINUTES);
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ExternalCredsException("publisher shutdown interrupted", e);
          }
        });
  }
}
