package io.quarkiverse.spdx.v3.deployment;

import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/**
 * SPDX 3.0 SBOM generator configuration
 */
@ConfigMapping(prefix = "quarkus.spdx")
@ConfigRoot
public interface SpdxConfig {
    /**
     * Whether to skip SBOM generation
     */
    @WithDefault("false")
    boolean skip();
}
