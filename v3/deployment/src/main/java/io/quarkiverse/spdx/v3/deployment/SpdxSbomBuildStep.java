package io.quarkiverse.spdx.v3.deployment;

import io.quarkiverse.spdx.v3.generator.Spdx3SbomGenerator;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.AppModelProviderBuildItem;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.pkg.builditem.OutputTargetBuildItem;
import io.quarkus.deployment.sbom.ApplicationManifestsBuildItem;
import io.quarkus.deployment.sbom.SbomBuildItem;

/**
 * Generates SPDX 3.0 SBOMs for packaged applications.
 */
public class SpdxSbomBuildStep {

    @BuildStep
    public FeatureBuildItem feature() {
        return new FeatureBuildItem("spdx-v3");
    }

    @BuildStep
    public void generate(ApplicationManifestsBuildItem applicationManifestsBuildItem,
            OutputTargetBuildItem outputTargetBuildItem,
            AppModelProviderBuildItem appModelProviderBuildItem,
            SpdxConfig spdxConfig,
            BuildProducer<SbomBuildItem> sbomProducer) {
        if (spdxConfig.skip() || applicationManifestsBuildItem.getManifests().isEmpty()) {
            return;
        }
        var depInfoProviderSupplier = appModelProviderBuildItem.getDependencyInfoProvider();
        var depInfoProvider = depInfoProviderSupplier == null ? null : depInfoProviderSupplier.get();
        for (var manifest : applicationManifestsBuildItem.getManifests()) {
            for (var sbom : Spdx3SbomGenerator.newInstance()
                    .setManifest(manifest)
                    .setOutputDirectory(outputTargetBuildItem.getOutputDirectory())
                    .setEffectiveModelResolver(depInfoProvider == null ? null : depInfoProvider.getMavenModelResolver())
                    .generate()) {
                sbomProducer.produce(new SbomBuildItem(sbom));
            }
        }
    }
}
