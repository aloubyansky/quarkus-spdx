package io.quarkiverse.spdx.it;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.spdx.it.app.GreetingResource;
import io.quarkus.test.ProdBuildResults;
import io.quarkus.test.ProdModeTestResults;
import io.quarkus.test.QuarkusProdModeTest;

public class MutableJarSpdxSbomIT {

    @RegisterExtension
    static final QuarkusProdModeTest config = new QuarkusProdModeTest()
            .withApplicationRoot((jar) -> jar.addClass(GreetingResource.class))
            .setApplicationName("simple-rest")
            .setApplicationVersion("1.0-SNAPSHOT")
            .overrideConfigKey("quarkus.package.jar.type", "mutable-jar");

    @ProdBuildResults
    ProdModeTestResults prodModeTestResults;

    @Test
    void testSpdxSbomGeneratedForMutableJar() throws Exception {
        SpdxSbomAssertions.verifySpdxSbom(prodModeTestResults);
    }
}
