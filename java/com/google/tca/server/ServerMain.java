/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.tca.server;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import com.google.common.flogger.FluentLogger;
import com.google.inject.Guice;
import com.google.inject.Injector;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;

/** An Armeria server that hosts the TransparentCaService with gRPC and REST support. */
public class ServerMain {
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  public static void main(String[] args) throws Exception {
    HelpArgs helpArgs = new HelpArgs();
    KmsArgs kmsArgs = new KmsArgs();
    LocalArgs localArgs = new LocalArgs();

    JCommander jc =
        JCommander.newBuilder()
            .addObject(helpArgs)
            .addCommand(kmsArgs)
            .addCommand(localArgs)
            .build();
    jc.setProgramName("server_main");
    try {
      jc.parse(args);
    } catch (ParameterException e) {
      jc.usage();
      throw e;
    }

    if (helpArgs.isHelp()) {
      jc.usage();
      return;
    }

    String parsedCommand = jc.getParsedCommand();
    Injector injector;
    if (LocalArgs.COMMAND_NAME.equals(parsedCommand)) {
      logger.atInfo().log("Starting in Local Mode");
      injector = Guice.createInjector(new TransparentCaModule(), new LocalModeModule(localArgs));
    } else if (KmsArgs.COMMAND_NAME.equals(parsedCommand)) {
      logger.atInfo().log("Starting in KMS Mode");
      injector = Guice.createInjector(new TransparentCaModule(), new KmsModeModule(kmsArgs));
    } else {
      logger.atInfo().log(
          "No command specified. Defaulting to KMS Mode with default configuration.");
      injector = Guice.createInjector(new TransparentCaModule(), new KmsModeModule(kmsArgs));
    }

    TransparentCertificateAuthorityGrpcHandler service =
        injector.getInstance(TransparentCertificateAuthorityGrpcHandler.class);
    TrustedCertificateAuthorityGrpcHandler legacyService =
        injector.getInstance(TrustedCertificateAuthorityGrpcHandler.class);
    JwtInterceptor jwtInterceptor = injector.getInstance(JwtInterceptor.class);
    PrometheusMeterRegistry meterRegistry = injector.getInstance(PrometheusMeterRegistry.class);
    CertificateValidityReporter validityReporter =
        injector.getInstance(CertificateValidityReporter.class);
    validityReporter.startAsync();

    int port = 50051;
    TcaServer tcaServer =
        new TcaServer(port, service, legacyService, jwtInterceptor, meterRegistry);

    tcaServer.start().join();

    Runtime.getRuntime()
        .addShutdownHook(
            new Thread() {
              @Override
              public void run() {
                System.err.println("*** shutting down Armeria server since JVM is shutting down");
                tcaServer.stop().join();
                validityReporter.stopAsync();
                System.err.println("*** server shut down");
              }
            });

    try {
      tcaServer.blockUntilShutdown();
    } catch (InterruptedException e) {
      logger.atInfo().log("Server interrupted.");
    }
  }
}
