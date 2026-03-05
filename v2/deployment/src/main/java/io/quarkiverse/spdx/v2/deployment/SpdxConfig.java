package io.quarkiverse.spdx.v2.deployment;

import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/**
 * SPDX 2.3 SBOM generator configuration
 */
@ConfigMapping(prefix = "quarkus.spdx")
@ConfigRoot
public interface SpdxConfig {
    /**
     * Whether to skip SBOM generation
     */
    @WithDefault("false")
    boolean skip();

    /**
     * SBOM file format. Supported formats are {@code json} and {@code tag-value}.
     * The default format is JSON.
     * If both are desired then {@code all} could be used as the value of this option.
     *
     * @return SBOM file format
     */
    @WithDefault("json")
    String format();

    /**
     * Whether to include the license text into generated SBOMs.
     *
     * @return whether to include the license text into generated SBOMs
     */
    @WithDefault("false")
    boolean includeLicenseText();
}
