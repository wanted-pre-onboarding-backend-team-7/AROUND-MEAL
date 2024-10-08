package com.lucky.around.meal.datapipeline;

import java.time.Instant;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
@EnableAsync
public class DataPipeLineService {
  private static final int MAX_RETRY_COUNT = 3;
  private static final int RETRY_DELAY_MS = 5000;

  @Value("${API_MAX_INDEX}")
  private int MAX_INDEX;

  @Value("${API_PAGE_SIZE}")
  private int PAGE_SIZE;

  private final RawDataLoadService rawDataLoadService;
  private final DataProcessService dataProcessService;

  @Bean
  public ApplicationRunner initializer() {
    return args -> {
      log.info("애플리케이션 초기화!");
      executeDataPipeLine();
    };
  }

  @Async("taskExecutor")
  @Scheduled(cron = "0 0 1 * * ?") // 매일 오전 1시 실행
  //    @Scheduled(cron = "0 */5 * * * *") // 5분마다
  public void executeDataPipeLine() {
    log.info("데이터 파이프라인 시작 - 개수: {}", MAX_INDEX);

    Instant startTime = Instant.now(); // 작업 시작 시간 기록

    int startIndex = 1;
    int currentPage = 0;
    while (startIndex <= MAX_INDEX) {
      int endIndex = startIndex + PAGE_SIZE - 1;

      if (!loadRawData(startIndex, endIndex) || !processData(currentPage)) {
        break;
      }

      startIndex += PAGE_SIZE;
      currentPage++;
    }

    Instant endTime = Instant.now(); // 작업 종료 시간 기록
    long duration = java.time.Duration.between(startTime, endTime).toMillis();
    log.info("데이터 파이프라인 완료 - 개수: {}, 소요 시간: {} ms", MAX_INDEX, duration);
  }

  private boolean loadRawData(int startIndex, int endIndex) {
    for (int i = 1; i <= MAX_RETRY_COUNT; i++) {
      try {
        rawDataLoadService.executeRawDataLoad(startIndex, endIndex);
        log.info("데이터 읽어오기 완료 ({}번째 시도)", i);
        return true;
      } catch (Exception e) {
        log.error("데이터 읽어오기 실패 ({}번째 시도)", i, e);
        sleepBeforeRetry();
      }
    }

    log.error("데이터 읽어오기 실패 - 최대 재시도 횟수 초과");
    return false;
  }

  private boolean processData(int currentPage) {
    for (int i = 1; i <= MAX_RETRY_COUNT; i++) {
      try {
        dataProcessService.executeDataProcess(currentPage);
        log.info("데이터 가공하기 완료 ({}번째 시도)", i);
        return true;
      } catch (Exception e) {
        log.error("데이터 가공하기 실패 ({}번째 시도)", i, e);
        sleepBeforeRetry();
      }
    }

    log.error("데이터 가공하기 실패 - 최대 재시도 횟수 초과");
    return false;
  }

  private void sleepBeforeRetry() {
    try {
      log.info("{}초 대기, 재실행", RETRY_DELAY_MS);
      Thread.sleep(RETRY_DELAY_MS);
    } catch (InterruptedException e) {
      log.error("대기 error", e);
      Thread.currentThread().interrupt();
    }
  }
}
