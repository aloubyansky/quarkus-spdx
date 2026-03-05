package io.quarkiverse.spdx.it;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkus.test.ProdModeTestResults;

final class SpdxSbomAssertions {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private SpdxSbomAssertions() {
    }

    static void verifySpdxSbom(ProdModeTestResults prodModeTestResults) throws IOException {

        Path sbomFile = getSingleSbom(prodModeTestResults);

        JsonNode root = MAPPER.readTree(sbomFile.toFile());

        // Verify SPDX document metadata
        assertThat(root.get("spdxVersion").asText()).as("SPDX version").isEqualTo("SPDX-2.3");
        assertThat(root.get("dataLicense").asText()).as("data license").isEqualTo("CC0-1.0");
        assertThat(root.get("SPDXID").asText()).isEqualTo("SPDXRef-DOCUMENT");
        assertThat(root.get("documentNamespace")).as("document namespace").isNotNull();
        assertThat(root.get("name")).as("document name").isNotNull();

        // Verify creation info
        JsonNode creationInfo = root.get("creationInfo");
        assertThat(creationInfo).as("creation info").isNotNull();
        assertThat(creationInfo.get("created")).as("creation date").isNotNull();
        JsonNode creators = creationInfo.get("creators");
        assertThat(creators).as("creators").isNotNull();
        assertThat(creators.isArray()).isTrue();
        assertThat(creators.size()).as("creator count").isGreaterThan(0);

        // Verify packages
        JsonNode packages = root.get("packages");
        assertThat(packages).as("packages").isNotNull();
        assertThat(packages.isArray()).isTrue();

        // Verify each package has required fields
        for (JsonNode pkg : packages) {
            assertThat(pkg.get("SPDXID")).as("package SPDXID").isNotNull();
            assertThat(pkg.get("name")).as("package name").isNotNull();
            assertThat(pkg.get("downloadLocation")).as("package downloadLocation").isNotNull();
        }

        // Verify the SBOM includes quarkus-rest and quarkus-rest-deployment packages
        List<String> packageNames = StreamSupport.stream(packages.spliterator(), false)
                .map(pkg -> pkg.get("name").asText())
                .toList();
        assertThat(packageNames).as("package names")
                .anyMatch(name -> name.contains("quarkus-rest") && !name.contains("deployment"))
                .anyMatch(name -> name.contains("quarkus-rest-deployment"));

        // Verify at least one package has an external reference (PURL)
        assertThat(StreamSupport.stream(packages.spliterator(), false)
                .filter(pkg -> pkg.has("externalRefs"))
                .flatMap(pkg -> StreamSupport.stream(pkg.get("externalRefs").spliterator(), false))
                .anyMatch(ref -> "PACKAGE-MANAGER".equals(ref.path("referenceCategory").asText())
                        && ref.path("referenceLocator").asText().startsWith("pkg:maven/")))
                .as("at least one package has a PURL external reference")
                .isTrue();

        // Verify relationships
        JsonNode relationships = root.get("relationships");
        assertThat(relationships).as("relationships").isNotNull();
        assertThat(relationships.isArray()).isTrue();
        assertThat(relationships.size()).as("relationship count").isGreaterThan(0);

        // Verify DESCRIBES relationship exists
        assertThat(StreamSupport.stream(relationships.spliterator(), false)
                .anyMatch(rel -> "DESCRIBES".equals(rel.get("relationshipType").asText())))
                .as("DESCRIBES relationship")
                .isTrue();

        // Verify DEPENDS_ON relationships when there are dependencies
        if (packages.size() > 1) {
            assertThat(StreamSupport.stream(relationships.spliterator(), false)
                    .anyMatch(rel -> "DEPENDS_ON".equals(rel.get("relationshipType").asText())))
                    .as("DEPENDS_ON relationship")
                    .isTrue();
        }
    }

    private static Path getSingleSbom(ProdModeTestResults prodModeTestResults) throws IOException {
        List<Path> sbomFiles = collectSboms(prodModeTestResults);

        assertThat(sbomFiles).as("SPDX SBOM files").hasSize(1);

        Path sbomFile = sbomFiles.get(0);
        assertThat(Files.size(sbomFile)).as("SBOM file size").isGreaterThan(0);
        return sbomFile;
    }

    private static List<Path> collectSboms(ProdModeTestResults prodModeTestResults) throws IOException {
        Path buildDir = prodModeTestResults.getBuildDir();
        assertThat(buildDir).as("build directory").isNotNull();
        List<Path> sbomFiles;
        try (Stream<Path> walk = Files.walk(buildDir)) {
            sbomFiles = walk
                    .filter(p -> p.getFileName().toString().endsWith("-spdx.json"))
                    .toList();
        }
        assertThat(sbomFiles).as("SPDX SBOM files in " + buildDir).isNotEmpty();
        return sbomFiles;
    }
}
