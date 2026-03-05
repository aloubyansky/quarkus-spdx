package io.quarkiverse.spdx.it.v3;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.spdx.it.app.GreetingResource;
import io.quarkus.test.ProdBuildResults;
import io.quarkus.test.ProdModeTestResults;
import io.quarkus.test.QuarkusProdModeTest;

public class UberJarSpdx3SbomIT {

    @RegisterExtension
    static final QuarkusProdModeTest config = new QuarkusProdModeTest()
            .withApplicationRoot((jar) -> jar.addClass(GreetingResource.class))
            .setApplicationName("simple-rest")
            .setApplicationVersion("1.0-SNAPSHOT")
            .overrideConfigKey("quarkus.package.jar.type", "uber-jar");

    @ProdBuildResults
    ProdModeTestResults prodModeTestResults;

    @Test
    void testSpdxSbomGeneratedForUberJar() throws Exception {
        Spdx3SbomAssertions.verifySpdxSbom(prodModeTestResults);
    }
}
