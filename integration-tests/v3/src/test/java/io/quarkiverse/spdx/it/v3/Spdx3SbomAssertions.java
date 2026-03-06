package io.quarkiverse.spdx.it.v3;

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

final class Spdx3SbomAssertions {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Spdx3SbomAssertions() {
    }

    static void verifySpdxSbom(ProdModeTestResults prodModeTestResults) throws IOException {

        Path sbomFile = getSingleSbom(prodModeTestResults);

        JsonNode root = MAPPER.readTree(sbomFile.toFile());

        // Verify JSON-LD context
        assertThat(root.has("@context")).as("JSON-LD @context").isTrue();

        // Verify @graph array
        JsonNode graph = root.get("@graph");
        assertThat(graph).as("@graph").isNotNull();
        assertThat(graph.isArray()).isTrue();
        assertThat(graph.size()).as("@graph element count").isGreaterThan(0);

        // Collect elements by type
        List<JsonNode> allElements = StreamSupport.stream(graph.spliterator(), false).toList();

        List<JsonNode> documents = allElements.stream()
                .filter(e -> typeEquals(e, "SpdxDocument"))
                .toList();
        assertThat(documents).as("SpdxDocument elements").hasSize(1);

        JsonNode document = documents.get(0);
        assertThat(document.has("name")).as("document has name").isTrue();

        // Verify creation info is present (inlined or referenced)
        assertThat(document.has("creationInfo")).as("document has creationInfo").isTrue();
        // CreationInfo may be inlined as an object or referenced as a blank node
        JsonNode creationInfo = document.get("creationInfo");
        if (creationInfo.isObject()) {
            assertThat(creationInfo.get("specVersion").asText()).as("spec version").isEqualTo("3.0.1");
            assertThat(creationInfo.get("created")).as("creation date").isNotNull();
        }

        // Verify the SBOM root element
        List<JsonNode> sboms = allElements.stream()
                .filter(e -> typeEquals(e, "software_Sbom"))
                .toList();
        assertThat(sboms).as("software_Sbom elements").hasSize(1);

        // Verify packages
        List<JsonNode> packages = allElements.stream()
                .filter(e -> typeEquals(e, "software_Package"))
                .toList();
        assertThat(packages).as("software_Package elements").isNotEmpty();

        // Verify each package has required fields
        for (JsonNode pkg : packages) {
            assertThat(pkg.has("name")).as("package has name").isTrue();
        }

        // Verify the SBOM includes quarkus-rest and quarkus-rest-deployment packages
        List<String> packageNames = packages.stream()
                .map(pkg -> pkg.get("name").asText())
                .toList();
        assertThat(packageNames).as("package names")
                .anyMatch(name -> name.contains("quarkus-rest") && !name.contains("deployment"))
                .anyMatch(name -> name.contains("quarkus-rest-deployment"));

        // Verify at least one package has a PURL (first-class in SPDX 3.0)
        assertThat(packages.stream()
                .anyMatch(pkg -> pkg.has("software_packageUrl")
                        && pkg.get("software_packageUrl").asText().startsWith("pkg:maven/")))
                .as("at least one package has a PURL")
                .isTrue();

        // Verify relationships
        List<JsonNode> relationships = allElements.stream()
                .filter(e -> typeEquals(e, "Relationship"))
                .toList();

        if (packages.size() > 1) {
            // Verify dependsOn relationships exist
            assertThat(relationships.stream()
                    .anyMatch(rel -> "dependsOn".equals(rel.path("relationshipType").asText())))
                    .as("dependsOn relationship")
                    .isTrue();
        }
    }

    private static boolean typeEquals(JsonNode node, String expectedType) {
        JsonNode typeNode = node.get("type");
        return typeNode != null && expectedType.equals(typeNode.asText());
    }

    private static Path getSingleSbom(ProdModeTestResults prodModeTestResults) throws IOException {
        Path buildDir = prodModeTestResults.getBuildDir();
        assertThat(buildDir).as("build directory").isNotNull();
        List<Path> sbomFiles;
        try (Stream<Path> walk = Files.walk(buildDir)) {
            sbomFiles = walk
                    .filter(p -> p.getFileName().toString().endsWith("-spdx.json"))
                    .toList();
        }
        assertThat(sbomFiles).as("SPDX SBOM files in " + buildDir).isNotEmpty();
        assertThat(sbomFiles).as("SPDX SBOM files").hasSize(1);

        Path sbomFile = sbomFiles.get(0);
        assertThat(Files.size(sbomFile)).as("SBOM file size").isGreaterThan(0);
        return sbomFile;
    }
}
